const express = require('express');
const { hashPassword, verifyPassword } = require('./password');
const { Jsonator, Jsonizer } = require('./jwt');

const app = express();
app.use(express.json());

const PORT = 3000;
const JWT_SECRET = '980c0c8ab0d19c0163abdbba8e05b51b16a57faed75d5a2a52ca3348075dd5bd'; //https://jwtsecret.com/generate

const books = [
  { id: 1, title: '1984', author: 'George Orwell' },
  { id: 2, title: 'The Hobbit', author: 'J.R.R. Tolkien' },
];

const users = [];

function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Token required' });

  try {
    // the todo comment i deleted by mistake :D 
    const decoded = Jsonizer(token, JWT_SECRET);
    req.user = decoded; // since the authorizaAdmin is waiting for a user to verify 
    next();
  } catch {
    res.status(403).json({ message: 'Invalid token' });
  }
}

function authorizeAdmin(req, res, next) {
  if (req.user?.role !== 'admin')
    return res.status(403).json({ message: 'Admin role required' });

  next();
}

app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password || !role)
    return res.status(400).json({ message: 'All fields required' });

  const existingUser = users.find((u) => u.username === username);

  if (existingUser)
    return res.status(409).json({ message: 'User already exists' });

  // TODO: Hash password
  const hashedPassword = hashPassword(password);
  users.push({ username, password: hashedPassword, role });

  res.status(201).json({ message: 'User registered' });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username);

  // TODO: Verify password
  if (!verifyPassword(password, user.password))
    return res.status(401).json({ message: 'who are youuu!!! wrong password hesh' });
  // TODO: Sign JWT
  const token = Jsonator({ username, role: user.role }, JWT_SECRET, 120);
  res.json({ token });
});

app.get('/books', (req, res) => {
  res.json(books);
});

app.get('/books/:id', (req, res) => {
  const book = books.find((b) => b.id === parseInt(req.params.id));

  if (!book) return res.status(404).json({ message: 'Book not found' });

  res.json(book);
});

app.post('/books', authenticate, authorizeAdmin, (req, res) => {
  const { title, author } = req.body;
  const newBook = { id: books.length + 1, title, author };

  books.push(newBook);

  res.status(201).json(newBook);
});

app.put('/books/:id', authenticate, authorizeAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const book = books.find((b) => b.id === id);

  if (!book) return res.status(404).json({ message: 'Book not found' });

  const { title, author } = req.body;

  book.title = title ?? book.title;
  book.author = author ?? book.author;

  res.json(book);
});

app.delete('/books/:id', authenticate, authorizeAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const index = books.findIndex((b) => b.id === id);

  if (index === -1) return res.status(404).json({ message: 'Book not found' });

  const deleted = books.splice(index, 1);

  res.json(deleted[0]);
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
