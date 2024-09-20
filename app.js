require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const validator = require("validator");
const nodemailer = require("nodemailer");
const cors = require("cors"); // Importando cors

const app = express();
const User = require("./Models/User");

// Config JSON response
app.use(express.json());
app.use(cors({
    origin: ["https://pixelnest.vercel.app/login", "https://pixelnest.vercel.app"],
    allowedHeaders: "*",
}));

// Open Route
app.get("/", (req, res) => {
    res.status(200).json({ msg: "Bem-vindo à API!" });
});

// Private Route
app.get("/user/:id", checkToken, async (req, res) => {
    const id = req.params.id;
    const user = await User.findById(id, "-password");

    if (!user) {
        return res.status(404).json({ msg: "Usuário não encontrado!" });
    }

    res.status(200).json({ user });
});

// Middleware para checar token
function checkToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) return res.status(401).json({ msg: "Acesso negado!" });

    try {
        const secret = process.env.SECRET;
        const decoded = jwt.verify(token, secret);
        req.userId = decoded.id;
        next();
    } catch (err) {
        res.status(400).json({ msg: "O Token é inválido!" });
    }
}

// Validação de senha
function validatePassword(password) {
    const regex = /^(?=.*[A-Z])(?=.*[!@#$%^&*])(?=.*\d)[A-Za-z\d!@#$%^&*]{10,}$/;
    return regex.test(password);
}

// Rota de registro
app.post("/auth/register", async (req, res) => {
    const { name, username, email, birthdate, gender, password, confirmpassword } = req.body;

    // Validations
    if (!name || !username || !email || !birthdate || !gender || !password || !confirmpassword) {
        return res.status(422).json({ msg: "Todos os campos são obrigatórios!" });
    }

    if (!validator.isEmail(email)) {
        return res.status(422).json({ msg: "O e-mail é inválido!" });
    }

    if (!validatePassword(password)) {
        return res.status(422).json({ msg: "A senha deve ter pelo menos 10 caracteres, 1 letra maiúscula, 1 caractere especial e 1 número!" });
    }

    if (password !== confirmpassword) {
        return res.status(422).json({ msg: "A senha e a confirmação precisam ser iguais!" });
    }

    const userExists = await User.findOne({ $or: [{ email }, { username }] });
    if (userExists) {
        return res.status(422).json({ msg: "Por favor, utilize outro e-mail ou nome de usuário!" });
    }

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    const user = new User({
        name,
        username,
        email,
        birthdate,
        gender,
        password: passwordHash,
    });

    try {
        await user.save();
        res.status(201).json({ msg: "Usuário criado com sucesso!" });
    } catch (error) {
        res.status(500).json({ msg: error });
    }
});

// Rota de login
app.post("/auth/login", async (req, res) => {
    const { emailOrUsername, password } = req.body;

    if (!emailOrUsername || !password) {
        return res.status(422).json({ msg: "Email ou usuário e senha são obrigatórios!" });
    }

    const user = await User.findOne({ $or: [{ email: emailOrUsername }, { username: emailOrUsername }] });
    if (!user) {
        return res.status(404).json({ msg: "Usuário não encontrado!" });
    }

    const checkPassword = await bcrypt.compare(password, user.password);
    if (!checkPassword) {
        return res.status(422).json({ msg: "Senha inválida" });
    }

    // Gera o token de autenticação
    const secret = process.env.SECRET;
    const token = jwt.sign({ id: user._id }, secret, { expiresIn: '1h' });

    // Gera e armazena o código de 2FA e a data de expiração
    const twofaCode = Math.floor(100000 + Math.random() * 900000).toString(); // Código de 6 dígitos
    const expirationTime = Date.now() + 2 * 60 * 1000; // 2 minutos em milissegundos
    await User.updateOne({ _id: user._id }, { twofaCode, twofaExpires: expirationTime }); // Armazena o código e a expiração no banco de dados

    // Enviar e-mail com o código
    await sendEmail(user.email, `Seu código de 2FA é: ${twofaCode}`);

    res.status(200).json({ msg: "Autenticação realizada com sucesso! Verifique seu e-mail para o código de 2FA.", token });
});

// Rota de redefinição de senha
app.post("/auth/forgot-password", async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(422).json({ msg: "O e-mail é obrigatório!" });
    }

    const user = await User.findOne({ email });
    if (!user) {
        return res.status(404).json({ msg: "Usuário não encontrado!" });
    }

    const resetToken = jwt.sign({ id: user._id }, process.env.SECRET, { expiresIn: '1h' });
    await sendEmail(user.email, `Clique aqui para redefinir sua senha: http://suaurl.com/reset-password?token=${resetToken}`);

    res.status(200).json({ msg: "Verifique seu e-mail para redefinir a senha." });
});

// Rota para redefinir a senha
app.post("/auth/reset-password", async (req, res) => {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
        return res.status(422).json({ msg: "Token e nova senha são obrigatórios!" });
    }

    try {
        const decoded = jwt.verify(token, process.env.SECRET);
        const user = await User.findById(decoded.id);

        const salt = await bcrypt.genSalt(12);
        const passwordHash = await bcrypt.hash(newPassword, salt);
        user.password = passwordHash;
        await user.save();

        res.status(200).json({ msg: "Senha redefinida com sucesso!" });
    } catch (err) {
        res.status(400).json({ msg: "Token inválido ou expirado!" });
    }
});

// Rota para verificar o código de 2FA
app.post("/auth/verify-2fa", async (req, res) => {
    const { token, twofaCode } = req.body;

    if (!token || !twofaCode) {
        return res.status(422).json({ msg: "Token e código de 2FA são obrigatórios!" });
    }

    try {
        const secret = process.env.SECRET;
        const decoded = jwt.verify(token, secret);
        const user = await User.findById(decoded.id);

        // Verifica se o código de 2FA é válido e se não está expirado
        if (user.twofaCode !== twofaCode || Date.now() > user.twofaExpires) {
            return res.status(422).json({ msg: "Código de 2FA inválido ou expirado!" });
        }

        // Limpar o código de 2FA após a verificação
        await User.updateOne({ _id: user._id }, { twofaCode: null, twofaExpires: null });

        res.status(200).json({ msg: "2FA verificado com sucesso!" });
    } catch (err) {
        res.status(400).json({ msg: "Token inválido!" });
    }
});

// Função para enviar e-mail
async function sendEmail(destinatario, conteudo) {
    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: destinatario,
        subject: "Autenticação e Redefinição de Senha",
        text: conteudo,
    };

    await transporter.sendMail(mailOptions);
}

const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose
    .connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.3bwb3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`)
    .then(() => {
        console.log("Conectou ao banco!");
        const PORT = process.env.PORT || 3000; // Use a variável de ambiente PORT
        app.listen(PORT, () => {
            console.log(`Servidor rodando na porta ${PORT}`);
        });
    })
    .catch((err) => console.log(err));

