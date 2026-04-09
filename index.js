const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());

const SECRET_KEY = "super-secret-key-123"; // В реальных проектах хранится в .env

// Имитация базы данных
let users = [];
let posts = [
    { id: 1, title: "Первый пост", content: "Hello World", authorId: 1 }
];

// --- MIDDLEWARES (Промежуточное ПО) ---

// 1. Проверка авторизации (JWT)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: "Токен отсутствует" });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ message: "Неверный токен" });
        req.user = user; // Записываем данные юзера в запрос
        next();
    });
};

// 2. Проверка прав (Владелец или Админ)
const authorizeOwnerOrAdmin = (req, res, next) => {
    const postId = parseInt(req.params.id);
    const post = posts.find(p => p.id === postId);

    if (!post) return res.status(404).json({ message: "Пост не найден" });

    // Проверяем: совпадает ли ID автора или является ли пользователь админом
    if (post.authorId === req.user.id || req.user.role === 'admin') {
        next();
    } else {
        return res.status(403).json({ message: "Нет прав для этого действия" });
    }
};

// --- AUTH ROUTES ---

// Регистрация
app.post('/register', async (req, res) => {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const newUser = {
        id: Date.now(),
        username: req.body.username,
        password: hashedPassword,
        role: req.body.role || 'user' // По умолчанию обычный юзер
    };
    users.push(newUser);
    res.status(201).json({ message: "Пользователь создан" });
});

// Логин
app.post('/login', async (req, res) => {
    const user = users.find(u => u.username === req.body.username);
    if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
        return res.status(400).json({ message: "Неверные данные" });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY);
    res.json({ token });
});

// --- CRUD POSTS ---

// READ (Любой пользователь)
app.get('/posts', (req, res) => {
    res.json(posts);
});

// CREATE (Только авторизованный)
app.post('/posts', authenticateToken, (req, res) => {
    const newPost = {
        id: posts.length + 1,
        title: req.body.title,
        content: req.body.content,
        authorId: req.user.id // Берем ID из токена
    };
    posts.push(newPost);
    res.status(201).json(newPost);
});

// UPDATE (Владелец или Админ)
app.put('/posts/:id', authenticateToken, authorizeOwnerOrAdmin, (req, res) => {
    const post = posts.find(p => p.id === parseInt(req.params.id));
    post.title = req.body.title || post.title;
    post.content = req.body.content || post.content;
    res.json({ message: "Пост обновлен", post });
});

// DELETE (Владелец или Админ)
app.delete('/posts/:id', authenticateToken, authorizeOwnerOrAdmin, (req, res) => {
    posts = posts.filter(p => p.id !== parseInt(req.params.id));
    res.json({ message: "Пост удален" });
});

app.listen(3000, () => console.log('Server started on http://localhost:3000'));