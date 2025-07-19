const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
const methodOverride = require('method-override');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

const { initializeApp } = require('firebase/app');
const { getAuth, createUserWithEmailAndPassword, signInWithEmailAndPassword, sendEmailVerification } = require('firebase/auth');

const app = express();
const port = 8080;

// Firebase Configuration
const firebaseConfig = {
    apiKey: "AIzaSyDRUZJDZ-MsDd18pqgMneSTd4IImz1MBBs",
    authDomain: "readers-connect-cc16d.firebaseapp.com",
    projectId: "readers-connect-cc16d",
    storageBucket: "readers-connect-cc16d.firebasestorage.app",
    messagingSenderId: "877512893580",
    appId: "1:877512893580:web:36f3e621448bfe671687a9",
    measurementId: "G-EJYRM101XC"
};

// Initialize Firebase
const firebaseApp = initializeApp(firebaseConfig);
const auth = getAuth(firebaseApp);
console.log('Firebase initialized successfully:', firebaseApp.name);

// Database connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'mohitkapgate2004@#1234',
    database: 'readers_connect'
});

db.connect(err => {
    if (err) {
        console.error('MySQL Connection Error:', err);
        throw err;
    }
    console.log('MySQL Connected');
});

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(methodOverride('_method'));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false
}));

const storage = multer.diskStorage({
    destination: 'public/uploads/',
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage });

// Authentication middleware
const isAuthenticated = (req, res, next) => {
    if (req.session.user && req.session.user.is_verified) next();
    else res.redirect('/login');
};

// OTP generation
const generateOTP = () => {
    return crypto.randomInt(100000, 999999).toString();
};

// Routes
app.get('/', (req, res) => {
    res.render('Landing', { user: req.session.user });
});

// Login Routes
app.get('/login', (req, res) => {
    res.render('Login_page', { error: null });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    console.log('Login attempt:', { email, password });
    signInWithEmailAndPassword(auth, email, password)
        .then(userCredential => {
            console.log('Firebase login success:', userCredential.user.email);
            const user = userCredential.user;
            console.log('Email verified in Firebase:', user.emailVerified);
            db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
                if (err) {
                    console.error('MySQL Error:', err.message);
                    return res.status(500).send('Database error');
                }
                console.log('MySQL query result:', results);
                if (results.length === 0) {
                    console.log('User not found in MySQL');
                    return res.render('Login_page', { error: 'User not found in database. Please register.' });
                }
                console.log('User found in MySQL, proceeding...');
                if (!user.emailVerified) {
                    const mobileOTP = generateOTP();
                    db.query('UPDATE users SET mobile_otp = ? WHERE email = ?', [mobileOTP, email], (err) => {
                        if (err) {
                            console.error('MySQL Update Error:', err.message);
                            return res.status(500).send('Database update error');
                        }
                        console.log('Mobile OTP generated:', mobileOTP);
                        req.session.tempUser = { email, mobile: results[0].mobile, mobileOTP };
                        console.log('Session tempUser set:', req.session.tempUser);
                        console.log('Redirecting to /verify-otp');
                        res.redirect('/verify-otp');
                    });
                } else if (!results[0].is_verified) {
                    const mobileOTP = generateOTP();
                    db.query('UPDATE users SET mobile_otp = ? WHERE email = ?', [mobileOTP, email], (err) => {
                        if (err) {
                            console.error('MySQL Update Error:', err.message);
                            return res.status(500).send('Database update error');
                        }
                        console.log('Mobile OTP generated:', mobileOTP);
                        req.session.tempUser = { email, mobile: results[0].mobile, mobileOTP };
                        console.log('Session tempUser set:', req.session.tempUser);
                        console.log('Redirecting to /verify-otp');
                        res.redirect('/verify-otp');
                    });
                } else {
                    req.session.user = results[0];
                    console.log('Session user set:', req.session.user);
                    console.log('Redirecting to /home');
                    res.redirect('/home');
                }
            });
        })
        .catch(error => {
            console.error('Firebase Login Error:', error.code, error.message);
            res.render('Login_page', { error: 'Invalid email or password' });
        });
});

// Forgot Password Routes
app.get('/forgot-password', (req, res) => {
    res.render('Forgot_password', { error: null });
});

app.post('/forgot-password', (req, res) => {
    const { email } = req.body;
    db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
        if (err) throw err;
        if (results.length === 0) {
            return res.render('Forgot_password', { error: 'Email not found' });
        }
        const resetToken = generateOTP();
        const expiry = new Date(Date.now() + 10 * 60 * 1000);
        db.query('UPDATE users SET reset_token = ?, reset_expiry = ? WHERE email = ?', [resetToken, expiry, email], (err) => {
            if (err) throw err;
            req.session.tempUser = { email, mobile: results[0].mobile, resetToken };
            res.redirect('/reset-password');
        });
    });
});

app.get('/reset-password', (req, res) => {
    if (!req.session.tempUser) return res.redirect('/forgot-password');
    res.render('Reset_password', { error: null, email: req.session.tempUser.email, resetToken: req.session.tempUser.resetToken });
});

app.post('/reset-password', (req, res) => {
    const { otp, newPassword } = req.body;
    const { email } = req.session.tempUser;
    db.query('SELECT * FROM users WHERE email = ? AND reset_token = ? AND reset_expiry > NOW()', [email, otp], (err, results) => {
        if (err) throw err;
        if (results.length === 0) {
            return res.render('Reset_password', { error: 'Invalid or expired OTP', email, resetToken: req.session.tempUser.resetToken });
        }
        const hashedPassword = bcrypt.hashSync(newPassword, 10);
        db.query('UPDATE users SET password = ?, reset_token = NULL, reset_expiry = NULL WHERE email = ?', [hashedPassword, email], (err) => {
            if (err) throw err;
            delete req.session.tempUser;
            res.redirect('/login');
        });
    });
});

// Registration Routes
app.get('/Registration', (req, res) => {
    res.render('Registration_page', { error: null });
});

app.post('/Registration', (req, res) => {
    const { name, email, mobile, address, password } = req.body;
    db.query('SELECT email, mobile FROM users WHERE email = ? OR mobile = ?', [email, mobile], (err, results) => {
        if (err) throw err;
        if (results.length > 0) {
            const error = results.some(r => r.email === email) ? 'Email already registered' : 'Mobile number already registered';
            return res.render('Registration_page', { error });
        }
        const hashedPassword = bcrypt.hashSync(password, 10);
        createUserWithEmailAndPassword(auth, email, password)
            .then(userCredential => {
                const user = userCredential.user;
                sendEmailVerification(user).then(() => {
                    const mobileOTP = generateOTP();
                    db.query(
                        'INSERT INTO users (full_name, email, mobile, address, password, mobile_otp) VALUES (?, ?, ?, ?, ?, ?)',
                        [name, email, mobile, address, hashedPassword, mobileOTP],
                        (err) => {
                            if (err) throw err;
                            req.session.tempUser = { email, mobile, name, address, mobileOTP };
                            res.redirect('/verify-otp');
                        }
                    );
                });
            })
            .catch(error => {
                console.error('Firebase Registration Error:', error.message);
                res.render('Registration_page', { error: 'Registration failed: ' + error.message });
            });
    });
});

// OTP Verification Route
app.get('/verify-otp', (req, res) => {
    if (!req.session.tempUser) return res.redirect('/login');
    res.render('Verify_otp', { error: null, email: req.session.tempUser.email, mobile: req.session.tempUser.mobile, mobileOTP: req.session.tempUser.mobileOTP });
});

app.post('/verify-otp', (req, res) => {
    const { mobileOTP } = req.body;
    const { email, mobile } = req.session.tempUser;
    db.query('SELECT * FROM users WHERE email = ? AND mobile = ? AND mobile_otp = ?', [email, mobile, mobileOTP], (err, results) => {
        if (err) {
            console.error('MySQL Error:', err.message);
            throw err;
        }
        if (results.length === 0) {
            return res.render('Verify_otp', { error: 'Invalid Mobile OTP', email, mobile, mobileOTP: req.session.tempUser.mobileOTP });
        }
        const user = auth.currentUser;
        if (user && user.emailVerified) {
            db.query('UPDATE users SET is_verified = TRUE, mobile_otp = NULL WHERE email = ?', [email], (err) => {
                if (err) throw err;
                db.query('SELECT * FROM users WHERE email = ?', [email], (err, userResults) => {
                    if (err) throw err;
                    req.session.user = userResults[0];
                    delete req.session.tempUser;
                    console.log('User fully verified, redirecting to /home');
                    res.redirect('/home');
                });
            });
        } else {
            res.render('Verify_otp', { error: 'Please verify your email first', email, mobile, mobileOTP });
        }
    });
});


app.get('/home', isAuthenticated, (req, res) => {
    const userId = req.session.user.id;
    console.log('Logged-in userId:', userId); // Debug: Log the userId

    Promise.all([
        // Fetch available books
        db.promise().query('SELECT * FROM books WHERE available_quantity > 0'),
        // Fetch user's donations
        db.promise().query('SELECT d.*, b.title FROM donations d JOIN books b ON d.book_id = b.id WHERE d.user_id = ?', [userId]),
        // Fetch cart items
        db.promise().query('SELECT c.*, b.title, b.image_url FROM cart c JOIN books b ON c.book_id = b.id WHERE c.user_id = ?', [userId]),
        // Fetch books requested by other users that are not available
        db.promise().query(`
            SELECT r.*
            FROM requests r
            LEFT JOIN books b ON r.book_id = b.id
            WHERE r.user_id != ?
            AND (r.book_id IS NULL OR b.available_quantity = 0)
            AND r.status = 'Pending'
        `, [userId])
    ])
    .then(([booksResult, donationsResult, cartResult, otherRequestsResult]) => {
        const books = booksResult[0] || [];
        const donations = donationsResult[0] || [];
        const cartItems = cartResult[0] || [];
        const otherRequests = otherRequestsResult[0] || []; // Ensure otherRequests is always an array

        console.log('Books:', books.length);
        console.log('Donations:', donations.length);
        console.log('Cart Items:', cartItems.length);
        console.log('Other Requests:', otherRequests);

        res.render('Home', {
            user: req.session.user || {},
            books,
            donations,
            cartItems,
            otherRequests, // Ensure this is always passed
            searchQuery: null
        });
    })
    .catch(err => {
        console.error('Error fetching home data:', err.message);
        // Render the template with empty data to avoid breaking the page
        res.render('Home', {
            user: req.session.user || {},
            books: [],
            donations: [],
            cartItems: [],
            otherRequests: [], // Pass an empty array in case of error
            searchQuery: null,
            error: 'Failed to load home page data. Please try again later.'
        });
    });
});


// app.post('/home/search', isAuthenticated, (req, res) => {
//     console.log('Received POST /home/search with body:', req.body); // Debug log
//     const { searchQuery } = req.body;
//     if (!searchQuery) {
//         console.log('No searchQuery provided');
//         return res.render('Home', {
//             user: req.session.user || {},
//             books: [],
//             searchQuery: '',
//             error: 'Please enter a search term.'
//         });
//     }
//     db.query(
//         'SELECT * FROM books WHERE (title LIKE ? OR author LIKE ?) AND available_quantity > 0',
//         [`%${searchQuery}%`, `%${searchQuery}%`],
//         (err, books) => {
//             if (err) {
//                 console.error('Search query error:', err.message);
//                 return res.render('Home', {
//                     user: req.session.user || {},
//                     books: [],
//                     searchQuery: searchQuery,
//                     error: 'Failed to search. Please try again.'
//                 });
//             }
//             console.log('Search results:', books.length, 'books found');
//             res.render('Home', {
//                 user: req.session.user || {},
//                 books: books || [],
//                 searchQuery: searchQuery,
//                 error: null
//             });
//         }
//     );
// });
app.post('/home/search', isAuthenticated, (req, res) => {
    console.log('Received POST /home/search with body:', req.body); // Debug log
    const { searchQuery } = req.body;
    if (!searchQuery) {
        console.log('No searchQuery provided');
        return res.render('Home', {
            user: req.session.user || {},
            books: [],
            otherRequests: [], // Fallback for otherRequests
            searchQuery: '',
            error: 'Please enter a search term.'
        });
    }

    const userId = req.session.user.id;

    Promise.all([
        // Fetch books matching the search query
        db.promise().query('SELECT * FROM books WHERE (title LIKE ? OR author LIKE ?) AND available_quantity > 0', [`%${searchQuery}%`, `%${searchQuery}%`]),
        // Fetch books requested by other users that are not available
        db.promise().query(`
            SELECT r.*
            FROM requests r
            LEFT JOIN books b ON r.book_id = b.id
            WHERE r.user_id != ?
            AND (r.book_id IS NULL OR b.available_quantity = 0)
            AND r.status = 'Pending'
        `, [userId])
    ])
    .then(([booksResult, otherRequestsResult]) => {
        const books = booksResult[0] || [];
        const otherRequests = otherRequestsResult[0] || [];
        console.log('Search results:', books.length, 'books found');
        console.log('Other Requests:', otherRequests.length);

        res.render('Home', {
            user: req.session.user || {},
            books: books,
            otherRequests: otherRequests, // Pass otherRequests
            searchQuery: searchQuery,
            error: null
        });
    })
    .catch(err => {
        console.error('Search query error:', err.message);
        res.render('Home', {
            user: req.session.user || {},
            books: [],
            otherRequests: [], // Fallback for otherRequests
            searchQuery: searchQuery,
            error: 'Failed to search. Please try again.'
        });
    });
});
app.get('/notifications', isAuthenticated, (req, res) => {
    const userId = req.session.user.id;
    db.query('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC', [userId], (err, notifications) => {
        if (err) {
            console.error('Error fetching notifications:', err.message);
            return res.status(500).json({ error: 'Failed to load notifications' });
        }
        // Mark unread notifications as read
        db.query('UPDATE notifications SET status = "read" WHERE user_id = ? AND status = "unread"', [userId], (err) => {
            if (err) console.error('Error marking notifications as read:', err.message);
        });
        res.json(notifications);
    });
});
// Admin Dashboard Route
app.get('/admin', isAuthenticated, (req, res) => {
    if (req.session.user.role !== 'admin') {
        return res.status(403).send('Access Denied: Only admins can access this page.');
    }

    Promise.all([
        // Fetch summary data
        db.promise().query('SELECT COUNT(*) AS count FROM books'),
        db.promise().query('SELECT COUNT(*) AS count FROM users'),
        db.promise().query('SELECT COUNT(*) AS count FROM requests WHERE status = "Pending"'),
        db.promise().query('SELECT COUNT(*) AS count FROM donations'),
        db.promise().query('SELECT COUNT(*) AS count FROM cart'),
        // Fetch detailed data
        db.promise().query('SELECT * FROM books'),
        db.promise().query('SELECT * FROM users'),
        db.promise().query('SELECT r.*, u.full_name AS user_name FROM requests r JOIN users u ON r.user_id = u.id'),
        db.promise().query('SELECT d.*, u.full_name AS user_name, b.title AS book_title FROM donations d JOIN users u ON d.user_id = u.id JOIN books b ON d.book_id = b.id'),
        db.promise().query('SELECT c.*, u.full_name AS user_name, b.title AS book_title FROM cart c JOIN users u ON c.user_id = u.id JOIN books b ON c.book_id = b.id')
    ])
    .then(([bookCountResult, userCountResult, requestCountResult, donationCountResult, cartCountResult, booksResult, usersResult, requestsResult, donationsResult, cartResult]) => {
        const bookCount = bookCountResult[0][0].count;
        const userCount = userCountResult[0][0].count;
        const requestCount = requestCountResult[0][0].count;
        const donationCount = donationCountResult[0][0].count;
        const cartCount = cartCountResult[0][0].count;
        const books = booksResult[0] || [];
        const users = usersResult[0] || [];
        const requests = requestsResult[0] || [];
        const donations = donationsResult[0] || [];
        const cartItems = cartResult[0] || [];

        res.render('Admin_dashboard', {
            bookCount,
            userCount,
            requestCount,
            donationCount,
            cartCount,
            books,
            users,
            requests,
            donations,
            cartItems,
            error: null,
            message: null
        });
    })
    .catch(err => {
        console.error('Error fetching admin dashboard data:', err.message);
        res.render('Admin_dashboard', {
            bookCount: 0,
            userCount: 0,
            requestCount: 0,
            donationCount: 0,
            cartCount: 0,
            books: [],
            users: [],
            requests: [],
            donations: [],
            cartItems: [],
            error: 'Failed to load dashboard data. Please try again later.',
            message: null
        });
    });
});

// Add a new book
app.post('/admin/books/add', isAuthenticated, upload.single('book_image'), (req, res) => {
    if (req.session.user.role !== 'admin') {
        return res.status(403).send('Access Denied: Only admins can access this page.');
    }

    const { title, author, category, description, available_quantity, isbn } = req.body;
    const image_url = req.file ? `/uploads/${req.file.filename}` : 'https://via.placeholder.com/150';

    if (!title || !author || !category || !available_quantity || !isbn) {
        return res.render('Admin_dashboard', {
            bookCount: 0,
            userCount: 0,
            requestCount: 0,
            donationCount: 0,
            cartCount: 0,
            books: [],
            users: [],
            requests: [],
            donations: [],
            cartItems: [],
            error: 'Please fill in all required fields.',
            message: null
        });
    }

    if (!/^[0-9]{13}$/.test(isbn)) {
        return res.render('Admin_dashboard', {
            bookCount: 0,
            userCount: 0,
            requestCount: 0,
            donationCount: 0,
            cartCount: 0,
            books: [],
            users: [],
            requests: [],
            donations: [],
            cartItems: [],
            error: 'ISBN must be exactly 13 digits.',
            message: null
        });
    }

    db.query(
        'INSERT INTO books (title, author, category, description, available_quantity, image_url, isbn) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [title, author, category, description || '', available_quantity, image_url, isbn],
        (err) => {
            if (err) {
                console.error('Error adding book:', err.message);
                return res.render('Admin_dashboard', {
                    bookCount: 0,
                    userCount: 0,
                    requestCount: 0,
                    donationCount: 0,
                    cartCount: 0,
                    books: [],
                    users: [],
                    requests: [],
                    donations: [],
                    cartItems: [],
                    error: 'Failed to add book. ISBN may already exist.',
                    message: null
                });
            }
            res.redirect('/admin');
        }
    );
});

// Update a book
app.post('/admin/books/update/:id', isAuthenticated, upload.single('book_image'), (req, res) => {
    if (req.session.user.role !== 'admin') {
        return res.status(403).send('Access Denied: Only admins can access this page.');
    }

    const bookId = req.params.id;
    const { title, author, category, description, available_quantity, isbn } = req.body;
    const image_url = req.file ? `/uploads/${req.file.filename}` : req.body.current_image_url;

    if (!title || !author || !category || !available_quantity || !isbn) {
        return res.render('Admin_dashboard', {
            bookCount: 0,
            userCount: 0,
            requestCount: 0,
            donationCount: 0,
            cartCount: 0,
            books: [],
            users: [],
            requests: [],
            donations: [],
            cartItems: [],
            error: 'Please fill in all required fields.',
            message: null
        });
    }

    if (!/^[0-9]{13}$/.test(isbn)) {
        return res.render('Admin_dashboard', {
            bookCount: 0,
            userCount: 0,
            requestCount: 0,
            donationCount: 0,
            cartCount: 0,
            books: [],
            users: [],
            requests: [],
            donations: [],
            cartItems: [],
            error: 'ISBN must be exactly 13 digits.',
            message: null
        });
    }

    db.query(
        'UPDATE books SET title = ?, author = ?, category = ?, description = ?, available_quantity = ?, image_url = ?, isbn = ? WHERE id = ?',
        [title, author, category, description || '', available_quantity, image_url, isbn, bookId],
        (err) => {
            if (err) {
                console.error('Error updating book:', err.message);
                return res.render('Admin_dashboard', {
                    bookCount: 0,
                    userCount: 0,
                    requestCount: 0,
                    donationCount: 0,
                    cartCount: 0,
                    books: [],
                    users: [],
                    requests: [],
                    donations: [],
                    cartItems: [],
                    error: 'Failed to update book.',
                    message: null
                });
            }
            res.redirect('/admin');
        }
    );
});

// Delete a book
app.post('/admin/books/delete/:id', isAuthenticated, (req, res) => {
    if (req.session.user.role !== 'admin') {
        return res.status(403).send('Access Denied: Only admins can access this page.');
    }

    const bookId = req.params.id;

    db.beginTransaction(err => {
        if (err) {
            console.error('Error starting transaction:', err.message);
            return res.render('Admin_dashboard', {
                bookCount: 0,
                userCount: 0,
                requestCount: 0,
                donationCount: 0,
                cartCount: 0,
                books: [],
                users: [],
                requests: [],
                donations: [],
                cartItems: [],
                error: 'Server Error',
                message: null
            });
        }

        db.query('DELETE FROM cart WHERE book_id = ?', [bookId], (err) => {
            if (err) {
                return db.rollback(() => {
                    console.error('Error deleting cart items:', err.message);
                    res.render('Admin_dashboard', {
                        bookCount: 0,
                        userCount: 0,
                        requestCount: 0,
                        donationCount: 0,
                        cartCount: 0,
                        books: [],
                        users: [],
                        requests: [],
                        donations: [],
                        cartItems: [],
                        error: 'Server Error',
                        message: null
                    });
                });
            }

            db.query('DELETE FROM donations WHERE book_id = ?', [bookId], (err) => {
                if (err) {
                    return db.rollback(() => {
                        console.error('Error deleting donations:', err.message);
                        res.render('Admin_dashboard', {
                            bookCount: 0,
                            userCount: 0,
                            requestCount: 0,
                            donationCount: 0,
                            cartCount: 0,
                            books: [],
                            users: [],
                            requests: [],
                            donations: [],
                            cartItems: [],
                            error: 'Server Error',
                            message: null
                        });
                    });
                }

                db.query('UPDATE requests SET book_id = NULL WHERE book_id = ?', [bookId], (err) => {
                    if (err) {
                        return db.rollback(() => {
                            console.error('Error updating requests:', err.message);
                            res.render('Admin_dashboard', {
                                bookCount: 0,
                                userCount: 0,
                                requestCount: 0,
                                donationCount: 0,
                                cartCount: 0,
                                books: [],
                                users: [],
                                requests: [],
                                donations: [],
                                cartItems: [],
                                error: 'Server Error',
                                message: null
                            });
                        });
                    }

                    db.query('DELETE FROM books WHERE id = ?', [bookId], (err, result) => {
                        if (err) {
                            return db.rollback(() => {
                                console.error('Error deleting book:', err.message);
                                res.render('Admin_dashboard', {
                                    bookCount: 0,
                                    userCount: 0,
                                    requestCount: 0,
                                    donationCount: 0,
                                    cartCount: 0,
                                    books: [],
                                    users: [],
                                    requests: [],
                                    donations: [],
                                    cartItems: [],
                                    error: 'Server Error',
                                    message: null
                                });
                            });
                        }

                        if (result.affectedRows === 0) {
                            return db.rollback(() => {
                                res.render('Admin_dashboard', {
                                    bookCount: 0,
                                    userCount: 0,
                                    requestCount: 0,
                                    donationCount: 0,
                                    cartCount: 0,
                                    books: [],
                                    users: [],
                                    requests: [],
                                    donations: [],
                                    cartItems: [],
                                    error: 'Book not found.',
                                    message: null
                                });
                            });
                        }

                        db.commit(err => {
                            if (err) {
                                return db.rollback(() => {
                                    console.error('Error committing transaction:', err.message);
                                    res.render('Admin_dashboard', {
                                        bookCount: 0,
                                        userCount: 0,
                                        requestCount: 0,
                                        donationCount: 0,
                                        cartCount: 0,
                                        books: [],
                                        users: [],
                                        requests: [],
                                        donations: [],
                                        cartItems: [],
                                        error: 'Server Error',
                                        message: null
                                    });
                                });
                            }
                            res.redirect('/admin');
                        });
                    });
                });
            });
        });
    });
});

// Update request status
app.post('/admin/requests/update/:id', isAuthenticated, (req, res) => {
    if (req.session.user.role !== 'admin') {
        return res.status(403).send('Access Denied: Only admins can access this page.');
    }

    const requestId = req.params.id;
    const { status } = req.body;

    db.query('UPDATE requests SET status = ? WHERE id = ?', [status, requestId], (err, result) => {
        if (err) {
            console.error('Error updating request:', err.message);
            return res.render('Admin_dashboard', {
                bookCount: 0,
                userCount: 0,
                requestCount: 0,
                donationCount: 0,
                cartCount: 0,
                books: [],
                users: [],
                requests: [],
                donations: [],
                cartItems: [],
                error: 'Failed to update request.',
                message: null
            });
        }
        if (result.affectedRows === 0) {
            return res.render('Admin_dashboard', {
                bookCount: 0,
                userCount: 0,
                requestCount: 0,
                donationCount: 0,
                cartCount: 0,
                books: [],
                users: [],
                requests: [],
                donations: [],
                cartItems: [],
                error: 'Request not found.',
                message: null
            });
        }
        res.redirect('/admin');
    });
});

// Delete a request
app.post('/admin/requests/delete/:id', isAuthenticated, (req, res) => {
    if (req.session.user.role !== 'admin') {
        return res.status(403).send('Access Denied: Only admins can access this page.');
    }

    const requestId = req.params.id;

    db.query('DELETE FROM requests WHERE id = ?', [requestId], (err, result) => {
        if (err) {
            console.error('Error deleting request:', err.message);
            return res.render('Admin_dashboard', {
                bookCount: 0,
                userCount: 0,
                requestCount: 0,
                donationCount: 0,
                cartCount: 0,
                books: [],
                users: [],
                requests: [],
                donations: [],
                cartItems: [],
                error: 'Failed to delete request.',
                message: null
            });
        }
        if (result.affectedRows === 0) {
            return res.render('Admin_dashboard', {
                bookCount: 0,
                userCount: 0,
                requestCount: 0,
                donationCount: 0,
                cartCount: 0,
                books: [],
                users: [],
                requests: [],
                donations: [],
                cartItems: [],
                error: 'Request not found.',
                message: null
            });
        }
        res.redirect('/admin');
    });
});

// Delete a donation
app.post('/admin/donations/delete/:id', isAuthenticated, (req, res) => {
    if (req.session.user.role !== 'admin') {
        return res.status(403).send('Access Denied: Only admins can access this page.');
    }

    const donationId = req.params.id;

    db.query('DELETE FROM donations WHERE id = ?', [donationId], (err, result) => {
        if (err) {
            console.error('Error deleting donation:', err.message);
            return res.render('Admin_dashboard', {
                bookCount: 0,
                userCount: 0,
                requestCount: 0,
                donationCount: 0,
                cartCount: 0,
                books: [],
                users: [],
                requests: [],
                donations: [],
                cartItems: [],
                error: 'Failed to delete donation.',
                message: null
            });
        }
        if (result.affectedRows === 0) {
            return res.render('Admin_dashboard', {
                bookCount: 0,
                userCount: 0,
                requestCount: 0,
                donationCount: 0,
                cartCount: 0,
                books: [],
                users: [],
                requests: [],
                donations: [],
                cartItems: [],
                error: 'Donation not found.',
                message: null
            });
        }
        res.redirect('/admin');
    });
});

// Delete a cart item
app.post('/admin/cart/delete/:id', isAuthenticated, (req, res) => {
    if (req.session.user.role !== 'admin') {
        return res.status(403).send('Access Denied: Only admins can access this page.');
    }

    const cartId = req.params.id;

    db.query('DELETE FROM cart WHERE id = ?', [cartId], (err, result) => {
        if (err) {
            console.error('Error deleting cart item:', err.message);
            return res.render('Admin_dashboard', {
                bookCount: 0,
                userCount: 0,
                requestCount: 0,
                donationCount: 0,
                cartCount: 0,
                books: [],
                users: [],
                requests: [],
                donations: [],
                cartItems: [],
                error: 'Failed to delete cart item.',
                message: null
            });
        }
        if (result.affectedRows === 0) {
            return res.render('Admin_dashboard', {
                bookCount: 0,
                userCount: 0,
                requestCount: 0,
                donationCount: 0,
                cartCount: 0,
                books: [],
                users: [],
                requests: [],
                donations: [],
                cartItems: [],
                error: 'Cart item not found.',
                message: null
            });
        }
        res.redirect('/admin');
    });
});

// Delete a user
app.post('/admin/users/delete/:id', isAuthenticated, (req, res) => {
    if (req.session.user.role !== 'admin') {
        return res.status(403).send('Access Denied: Only admins can access this page.');
    }

    const userId = req.params.id;

    // Prevent deleting the admin user
    if (userId == req.session.user.id) {
        return res.render('Admin_dashboard', {
            bookCount: 0,
            userCount: 0,
            requestCount: 0,
            donationCount: 0,
            cartCount: 0,
            books: [],
            users: [],
            requests: [],
            donations: [],
            cartItems: [],
            error: 'Cannot delete the admin user.',
            message: null
        });
    }

    db.beginTransaction(err => {
        if (err) {
            console.error('Error starting transaction:', err.message);
            return res.render('Admin_dashboard', {
                bookCount: 0,
                userCount: 0,
                requestCount: 0,
                donationCount: 0,
                cartCount: 0,
                books: [],
                users: [],
                requests: [],
                donations: [],
                cartItems: [],
                error: 'Server Error',
                message: null
            });
        }

        db.query('DELETE FROM cart WHERE user_id = ?', [userId], (err) => {
            if (err) {
                return db.rollback(() => {
                    console.error('Error deleting cart items:', err.message);
                    res.render('Admin_dashboard', {
                        bookCount: 0,
                        userCount: 0,
                        requestCount: 0,
                        donationCount: 0,
                        cartCount: 0,
                        books: [],
                        users: [],
                        requests: [],
                        donations: [],
                        cartItems: [],
                        error: 'Server Error',
                        message: null
                    });
                });
            }

            db.query('DELETE FROM donations WHERE user_id = ?', [userId], (err) => {
                if (err) {
                    return db.rollback(() => {
                        console.error('Error deleting donations:', err.message);
                        res.render('Admin_dashboard', {
                            bookCount: 0,
                            userCount: 0,
                            requestCount: 0,
                            donationCount: 0,
                            cartCount: 0,
                            books: [],
                            users: [],
                            requests: [],
                            donations: [],
                            cartItems: [],
                            error: 'Server Error',
                            message: null
                        });
                    });
                }

                db.query('DELETE FROM requests WHERE user_id = ?', [userId], (err) => {
                    if (err) {
                        return db.rollback(() => {
                            console.error('Error deleting requests:', err.message);
                            res.render('Admin_dashboard', {
                                bookCount: 0,
                                userCount: 0,
                                requestCount: 0,
                                donationCount: 0,
                                cartCount: 0,
                                books: [],
                                users: [],
                                requests: [],
                                donations: [],
                                cartItems: [],
                                error: 'Server Error',
                                message: null
                            });
                        });
                    }

                    db.query('DELETE FROM users WHERE id = ?', [userId], (err, result) => {
                        if (err) {
                            return db.rollback(() => {
                                console.error('Error deleting user:', err.message);
                                res.render('Admin_dashboard', {
                                    bookCount: 0,
                                    userCount: 0,
                                    requestCount: 0,
                                    donationCount: 0,
                                    cartCount: 0,
                                    books: [],
                                    users: [],
                                    requests: [],
                                    donations: [],
                                    cartItems: [],
                                    error: 'Server Error',
                                    message: null
                                });
                            });
                        }

                        if (result.affectedRows === 0) {
                            return db.rollback(() => {
                                res.render('Admin_dashboard', {
                                    bookCount: 0,
                                    userCount: 0,
                                    requestCount: 0,
                                    donationCount: 0,
                                    cartCount: 0,
                                    books: [],
                                    users: [],
                                    requests: [],
                                    donations: [],
                                    cartItems: [],
                                    error: 'User not found.',
                                    message: null
                                });
                            });
                        }

                        db.commit(err => {
                            if (err) {
                                return db.rollback(() => {
                                    console.error('Error committing transaction:', err.message);
                                    res.render('Admin_dashboard', {
                                        bookCount: 0,
                                        userCount: 0,
                                        requestCount: 0,
                                        donationCount: 0,
                                        cartCount: 0,
                                        books: [],
                                        users: [],
                                        requests: [],
                                        donations: [],
                                        cartItems: [],
                                        error: 'Server Error',
                                        message: null
                                    });
                                });
                            }
                            res.redirect('/admin');
                        });
                    });
                });
            });
        });
    });
});


// Book Template Route
app.get('/templet/:id', isAuthenticated, (req, res) => {
    const bookId = req.params.id;
    db.query('SELECT * FROM books WHERE id = ?', [bookId], (err, results) => {
        if (err) throw err;
        if (results.length === 0) return res.status(404).send('Book not found');
        res.render('Booktemp', { user: req.session.user, book: results[0] });
    });
});


app.get('/donate/:id', isAuthenticated, (req, res) => {
    const requestId = req.params.id;
    db.query(
        'SELECT * FROM requests WHERE id = ? AND status = "Pending"',
        [requestId],
        (err, results) => {
            if (err) {
                console.error('Error fetching request:', err.message);
                return res.render('Donate_general', { error: 'Failed to load request. Please try again.', request: null });
            }
            if (results.length === 0) {
                return res.render('Donate_general', { error: 'Request not found or already fulfilled.', request: null });
            }
            const request = results[0];
            res.render('Donate_general', { request, error: null });
        }
    );
});
app.get('/donate', isAuthenticated, (req, res) => {
    const requestId = req.query.request_id; // Get request_id from query parameters

    if (requestId) {
        // Fetch the request details if request_id is provided
        db.query(
            'SELECT * FROM requests WHERE id = ? AND status = "Pending"',
            [requestId],
            (err, results) => {
                if (err) {
                    console.error('Error fetching request:', err.message);
                    return res.render('Donate_general', {
                        user: req.session.user || {},
                        request: null,
                        error: 'Failed to load request. Please try again.'
                    });
                }
                if (results.length === 0) {
                    return res.render('Donate_general', {
                        user: req.session.user || {},
                        request: null,
                        error: 'Request not found or already fulfilled.'
                    });
                }
                const request = results[0];
                res.render('Donate_general', {
                    user: req.session.user || {},
                    request,
                    error: null
                });
            }
        );
    } else {
        // No request_id, render the form without pre-filled data
        res.render('Donate_general', {
            user: req.session.user || {},
            request: null,
            error: null
        });
    }
});


// app.post('/donate', isAuthenticated, upload.single('book_image'), (req, res) => {
//     const userId = req.session.user.id;
//     const { title, author, category, description, quantity, house_no, street, city, state, pincode, landmark, country_code, mobile, request_id } = req.body;
//     const image_url = req.file ? `/uploads/${req.file.filename}` : 'https://via.placeholder.com/150';

//     // Insert the book into the books table
//     db.query(
//         'INSERT INTO books (title, author, category, description, available_quantity, image_url) VALUES (?, ?, ?, ?, ?, ?)',
//         [title, author, category, description || '', quantity, image_url],
//         (err, result) => {
//             if (err) {
//                 console.error('Error inserting book:', err.message);
//                 return res.render('Donate_general', { error: 'Failed to donate book. Please try again.', request: null });
//             }

//             const bookId = result.insertId;

//             // Insert the donation into the donations table
//             db.query(
//                 'INSERT INTO donations (user_id, book_id, quantity, house_no, street, city, state, pincode, landmark, mobile) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
//                 [userId, bookId, quantity, house_no, street, city, state, pincode, landmark || '', `${country_code}${mobile}`],
//                 (err) => {
//                     if (err) {
//                         console.error('Error inserting donation:', err.message);
//                         return res.render('Donate_general', { error: 'Failed to record donation. Please try again.', request: null });
//                     }

//                     // If this donation fulfills a request, update the request status and link the book
//                     if (request_id) {
//                         db.query(
//                             'UPDATE requests SET book_id = ?, status = "Fulfilled" WHERE id = ? AND status = "Pending"',
//                             [bookId, request_id],
//                             (err) => {
//                                 if (err) {
//                                     console.error('Error updating request:', err.message);
//                                 }
//                                 res.redirect('/home');
//                             }
//                         );
//                     } else {
//                         res.redirect('/home');
//                     }
//                 }
//             );
//         }
//     );
// });
app.post('/donate', isAuthenticated, upload.single('book_image'), (req, res) => {
    const userId = req.session.user.id;
    const { title, author, category, description, quantity, house_no, street, city, state, pincode, landmark, country_code, mobile, request_id, isbn } = req.body; // Added isbn
    const image_url = req.file ? `/uploads/${req.file.filename}` : 'https://via.placeholder.com/150';

    // Insert the book into the books table with ISBN
    db.query(
        'INSERT INTO books (title, author, category, description, available_quantity, image_url, isbn) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [title, author, category, description || '', quantity, image_url, isbn],
        (err, result) => {
            if (err) {
                console.error('Error inserting book:', err.message);
                return res.render('Donate_general', { error: 'Failed to donate book. Please try again.', request: req.query.request_id ? { id: req.query.request_id } : null });
            }

            const bookId = result.insertId;

            // Insert the donation into the donations table
            db.query(
                'INSERT INTO donations (user_id, book_id, quantity, house_no, street, city, state, pincode, landmark, mobile) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [userId, bookId, quantity, house_no, street, city, state, pincode, landmark || '', `${country_code}${mobile}`],
                (err) => {
                    if (err) {
                        console.error('Error inserting donation:', err.message);
                        return res.render('Donate_general', { error: 'Failed to record donation. Please try again.', request: req.query.request_id ? { id: req.query.request_id } : null });
                    }

                    // If this donation fulfills a request, update the request status and link the book
                    if (request_id) {
                        db.query(
                            'UPDATE requests SET book_id = ?, status = "Fulfilled" WHERE id = ? AND status = "Pending"',
                            [bookId, request_id],
                            (err) => {
                                if (err) {
                                    console.error('Error updating request:', err.message);
                                }
                                res.redirect('/home');
                            }
                        );
                    } else {
                        res.redirect('/home');
                    }
                }
            );
        }
    );
});
// Request Routes
app.get('/request/:id', isAuthenticated, (req, res) => {
    const bookId = req.params.id;
    db.query('SELECT * FROM books WHERE id = ?', [bookId], (err, results) => {
        if (err) throw err;
        if (results.length === 0) return res.status(404).send('Book not found');
        res.render('Request_book', { user: req.session.user, book: results[0], error: null });
    });
});


app.post('/request', isAuthenticated, (req, res) => {
    const userId = req.session.user.id;
    const { title, author, category, description, quantity, house_no, street, city, state, pincode, landmark, country_code, mobile } = req.body;

    // Log the incoming form data for debugging
    console.log('Form data:', req.body);

    // Validate required fields
    if (!title || !author || !category || !quantity || !house_no || !street || !city || !state || !pincode || !country_code || !mobile) {
        console.error('Validation error: Missing required fields');
        return res.render('Request_general', { error: 'Please fill in all required fields.' });
    }

    // Ensure description and landmark are strings (even if empty)
    const safeDescription = description || '';
    const safeLandmark = landmark || '';

    // Combine country code and mobile number
    const fullMobile = `${country_code}${mobile}`;

    db.query(
        'INSERT INTO requests (user_id, book_id, title, author, category, description, quantity, house_no, street, city, state, pincode, landmark, mobile, status) VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "Pending")',
        [userId, title, author, category, safeDescription, quantity, house_no, street, city, state, pincode, safeLandmark, fullMobile],
        (err) => {
            if (err) {
                console.error('Error inserting request:', err.message);
                console.error('SQL Error Details:', err.sqlMessage); // Log detailed SQL error
                return res.render('Request_general', { error: 'Failed to request book. Please try again.' });
            }
            console.log('Book request successfully inserted');
            res.redirect('/home');
        }
    );
});


// General Donate and Request Routes
app.get('/donate', isAuthenticated, (req, res) => {
    res.render('Donate_general', { user: req.session.user, error: null });
});

// app.post('/donate', isAuthenticated, upload.single('book_image'), (req, res) => {
//     const { title, author, category, quantity } = req.body;
//     const userId = req.session.user.id;
//     const imageUrl = req.file ? `/uploads/${req.file.filename}` : 'https://via.placeholder.com/150';

//     if (!title || !author || !category || quantity < 1) {
//         return res.render('Donate_general', { user: req.session.user, error: 'All fields are required and quantity must be at least 1' });
//     }

//     db.query(
//         'INSERT INTO books (title, author, category, image_url, available_quantity) VALUES (?, ?, ?, ?, ?)',
//         [title, author, category, imageUrl, quantity],
//         (err, result) => {
//             if (err) throw err;
//             const bookId = result.insertId;
//             db.query('INSERT INTO donations (user_id, book_id, quantity) VALUES (?, ?, ?)', [userId, bookId, quantity], (err) => {
//                 if (err) throw err;
//                 res.redirect('/home');
//             });
//         }
//     );
// });

app.post('/donate', isAuthenticated, upload.single('book_image'), (req, res) => {
    const userId = req.session.user.id;
    const { title, author, category, description, quantity, house_no, street, city, state, pincode, landmark, country_code, mobile, request_id, isbn } = req.body;
    const image_url = req.file ? `/uploads/${req.file.filename}` : 'https://via.placeholder.com/150';

    db.query(
        'INSERT INTO books (title, author, category, description, available_quantity, image_url, isbn) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [title, author, category, description || '', quantity, image_url, isbn],
        (err, result) => {
            if (err) {
                console.error('Error inserting book:', err.message);
                return res.render('Donate_general', { error: 'Failed to donate book. Please try again.', request: req.query.request_id ? { id: req.query.request_id } : null });
            }

            const bookId = result.insertId;

            db.query(
                'INSERT INTO donations (user_id, book_id, quantity, house_no, street, city, state, pincode, landmark, mobile) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [userId, bookId, quantity, house_no, street, city, state, pincode, landmark || '', `${country_code}${mobile}`],
                (err) => {
                    if (err) {
                        console.error('Error inserting donation:', err.message);
                        return res.render('Donate_general', { error: 'Failed to record donation. Please try again.', request: req.query.request_id ? { id: req.query.request_id } : null });
                    }

                    // Notify the donor
                    const message = `Your donation of "${title}" has been accepted.`;
                    db.query(
                        'INSERT INTO notifications (user_id, message) VALUES (?, ?)',
                        [userId, message],
                        (err) => {
                            if (err) console.error('Error creating donation notification:', err.message);
                        }
                    );

                    if (request_id) {
                        db.query(
                            'UPDATE requests SET book_id = ?, status = "Fulfilled" WHERE id = ? AND status = "Pending"',
                            [bookId, request_id],
                            (err) => {
                                if (err) {
                                    console.error('Error updating request:', err.message);
                                }
                                res.redirect('/home');
                            }
                        );
                    } else {
                        res.redirect('/home');
                    }
                }
            );
        }
    );
});

// GET route to render the request form
app.get('/request', isAuthenticated, (req, res) => {
    res.render('Request_general', { error: null });
});

// POST route to handle book request submission
app.post('/request', isAuthenticated, (req, res) => {
    const userId = req.session.user.id;
    const { title, author, category, description, quantity, house_no, street, city, state, pincode, landmark, country_code, mobile } = req.body;

    console.log('Form data:', req.body);

    if (!title || !author || !category || !quantity || !house_no || !street || !city || !state || !pincode || !country_code || !mobile) {
        console.error('Validation error: Missing required fields');
        return res.render('Request_general', { error: 'Please fill in all required fields.' });
    }

    const safeDescription = description || '';
    const safeLandmark = landmark || '';
    const fullMobile = `${country_code}${mobile}`;

    db.query(
        'INSERT INTO requests (user_id, book_id, title, author, category, description, quantity, house_no, street, city, state, pincode, landmark, mobile, status) VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "Pending")',
        [userId, title, author, category, safeDescription, quantity, house_no, street, city, state, pincode, safeLandmark, fullMobile],
        (err) => {
            if (err) {
                console.error('Error inserting request:', err.message);
                console.error('SQL Error Details:', err.sqlMessage);
                return res.render('Request_general', { error: 'Failed to request book. Please try again.' });
            }
            console.log('Book request successfully inserted');
            res.redirect('/home');
        }
    );
});
// Cart Routes
app.get('/cart', isAuthenticated, (req, res) => {
    const userId = req.session.user.id;
    db.query('SELECT c.*, b.title, b.image_url FROM cart c JOIN books b ON c.book_id = b.id WHERE c.user_id = ?', [userId], (err, cartItems) => {
        if (err) throw err;
        res.render('Cart', { user: req.session.user, cartItems });
    });
});

app.post('/cart/add/:id', isAuthenticated, (req, res) => {
    const bookId = req.params.id;
    const userId = req.session.user.id;
    db.query('INSERT INTO cart (user_id, book_id) VALUES (?, ?)', [userId, bookId], (err) => {
        if (err) throw err;
        res.redirect('/home');
    });
});

app.post('/cart/remove/:id', isAuthenticated, (req, res) => {
    const cartId = req.params.id;
    const userId = req.session.user.id;
    db.query('DELETE FROM cart WHERE id = ? AND user_id = ?', [cartId, userId], (err) => {
        if (err) throw err;
        res.redirect('/cart');
    });
});

// Profile Routes
app.get('/profile', isAuthenticated, (req, res) => {
    res.render('Profile', { user: req.session.user });
});

app.get('/my-donations', isAuthenticated, (req, res) => {
    const userId = req.session.user.id;
    db.query('SELECT d.*, b.title FROM donations d JOIN books b ON d.book_id = b.id WHERE d.user_id = ?', [userId], (err, donations) => {
        if (err) throw err;
        res.render('My_donations', { user: req.session.user, donations });
    });
});

app.get('/my-requests', isAuthenticated, (req, res) => {
    const userId = req.session.user.id;
    db.query('SELECT r.*, b.title FROM requests r LEFT JOIN books b ON r.book_id = b.id WHERE r.user_id = ?', [userId], (err, requests) => {
        if (err) throw err;
        res.render('My_requests', { user: req.session.user, requests });
    });
});

app.get('/manage-requests', isAuthenticated, (req, res) => {
    db.query('SELECT r.*, u.full_name, b.title FROM requests r JOIN users u ON r.user_id = u.id LEFT JOIN books b ON r.book_id = b.id', (err, requests) => {
        if (err) throw err;
        res.render('Manage_requests', { user: req.session.user, requests });
    });
});


// app.post('/manage-requests/:id/:action', isAuthenticated, (req, res) => {
//     const requestId = req.params.id;
//     const action = req.params.action;
//     const status = action === 'approve' ? 'Approved' : 'Rejected';
//     db.query('UPDATE requests SET status = ? WHERE id = ?', [status, requestId], (err) => {
//         if (err) throw err;
//         if (action === 'approve') {
//             db.query('SELECT book_id, quantity FROM requests WHERE id = ?', [requestId], (err, result) => {
//                 if (err) throw err;
//                 if (result[0].book_id) {
//                     db.query('UPDATE books SET available_quantity = available_quantity - ? WHERE id = ?', [result[0].quantity, result[0].book_id], (err) => {
//                         if (err) throw err;
//                         res.redirect('/manage-requests');
//                     });
//                 } else {
//                     res.redirect('/manage-requests');
//                 }
//             });
//         } else {
//             res.redirect('/manage-requests');
//         }
//     });
// });
app.post('/manage-requests/:id/:action', isAuthenticated, (req, res) => {
    const requestId = req.params.id;
    const action = req.params.action;
    const status = action === 'approve' ? 'Approved' : 'Rejected';
    const userId = req.session.user.id;

    db.query('UPDATE requests SET status = ? WHERE id = ?', [status, requestId], (err, result) => {
        if (err) {
            console.error('Error updating request:', err.message);
            return res.render('Admin_dashboard', {
                section: 'requests',
                bookCount: 0, userCount: 0, requestCount: 0, donationCount: 0,
                books: [], users: [], requests: [], donations: [],
                error: 'Failed to update request.',
                message: null
            });
        }
        if (result.affectedRows === 0) {
            return res.render('Admin_dashboard', {
                section: 'requests',
                bookCount: 0, userCount: 0, requestCount: 0, donationCount: 0,
                books: [], users: [], requests: [], donations: [],
                error: 'Request not found.',
                message: null
            });
        }

        if (action === 'approve') {
            db.query('SELECT user_id, title, house_no, street, city, state, pincode, landmark FROM requests WHERE id = ?', [requestId], (err, request) => {
                if (err) {
                    console.error('Error fetching request details:', err.message);
                } else if (request.length > 0) {
                    const { user_id, title, house_no, street, city, state, pincode, landmark } = request[0];
                    const address = `${house_no}, ${street}, ${city}, ${state}, ${pincode}${landmark ? `, ${landmark}` : ''}`;
                    const message = `Your book request for "${title}" has been approved. Pickup address: ${address}`;
                    db.query(
                        'INSERT INTO notifications (user_id, message, address) VALUES (?, ?, ?)',
                        [user_id, message, address],
                        (err) => {
                            if (err) console.error('Error creating notification:', err.message);
                        }
                    );
                }
            });
            db.query('SELECT book_id, quantity FROM requests WHERE id = ?', [requestId], (err, result) => {
                if (err) throw err;
                if (result[0].book_id) {
                    db.query('UPDATE books SET available_quantity = available_quantity - ? WHERE id = ?', [result[0].quantity, result[0].book_id], (err) => {
                        if (err) throw err;
                        res.redirect('/admin?section=requests');
                    });
                } else {
                    res.redirect('/admin?section=requests');
                }
            });
        } else {
            res.redirect('/admin?section=requests');
        }
    });
});
// Contact Us Route
app.post('/contact', (req, res) => {
    const { name, phone, email, message } = req.body;
    db.query(
        'INSERT INTO contact_messages (name, phone, email, message) VALUES (?, ?, ?, ?)',
        [name, phone, email, message],
        (err) => {
            if (err) {
                console.error('Error saving contact message:', err);
                return res.status(500).send('Error submitting your message');
            }
            res.redirect('/home#contact-us');
        }
    );
});

// Static Pages
app.get('/about', (req, res) => {
    res.render('About', { user: req.session.user });
});

app.get('/blog', (req, res) => {
    db.query('SELECT b.*, u.full_name FROM blog_posts b JOIN users u ON b.author_id = u.id', (err, posts) => {
        if (err) throw err;
        res.render('Blog', { user: req.session.user, posts });
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

app.listen(port, () => {
    console.log(`Listening on port ${port}`);
});