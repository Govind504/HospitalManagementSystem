const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const admin = require('firebase-admin');
const path = require('path');

// Initialize Firebase Admin SDK
const serviceAccount = require('./hospitalmanagement-ed460-firebase-adminsdk-zzd63-52d9eea664.json'); // Update with the correct path

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: 'https://hospitalmanagement-ed460.firebaseio.com' // Replace with your project ID
});

const db = admin.firestore(); // Get a reference to Firestore
const usersCollection = db.collection('users');

const app = express();
const port = 3000;
const secretKey = 'your_secret_key';

app.use(bodyParser.json());
app.use(cors());
app.use(express.static(path.join(__dirname)));

// Signup endpoint
app.post('/signup', async (req, res) => {
    const { firstName, lastName, email, password } = req.body;
    console.log('Signup request received:', { firstName, lastName, email });
    if (!firstName || !lastName || !email || !password) {
        return res.status(400).send('All fields are required');
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = { firstName, lastName, email, password: hashedPassword };
        
        // Create user in Firebase Authentication
        const userRecord = await admin.auth().createUser({
            email: email,
            password: password,
            displayName: `${firstName} ${lastName}`
        });

        const uid = userRecord.uid; // Get the UID from Firebase Authentication

        // Store additional user details
        const username = `${firstName.toLowerCase()}${lastName.toLowerCase()}`;
        const profilePictureUrl = 'https://example.com/profile-picture.jpg'; // Replace with the actual URL

        // Save user data to Firestore using UID as document ID
        const userRef = usersCollection.doc(uid);
        await userRef.set({
            firstName: firstName,
            lastName: lastName,
            email: email,
            password: hashedPassword,
            username: username,
            profilePictureUrl: profilePictureUrl
        });

        console.log('User details stored successfully!');
        res.status(201).send({ message: 'User created', redirect: '/dashboard.html' });
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(400).send(`Error creating user: ${error.message}`);
    }
});

// Login endpoint
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    // Fetch user data from Firestore
    const userSnapshot = await usersCollection.where('email', '==', email).get();
    if (userSnapshot.empty) {
        return res.status(400).send('User not found');
    }
    const user = userSnapshot.docs[0].data();
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(400).send('Invalid password');
    }
    const token = jwt.sign({ userId: userSnapshot.docs[0].id }, secretKey);
    res.send({ token });
});

// Middleware to authenticate user
const authenticate = (req, res, next) => {
    const token = req.header('Authorization').replace('Bearer ', '');
    try {
        const decoded = jwt.verify(token, secretKey);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        res.status(401).send('Unauthorized');
    }
};

// Protected route example
app.get('/profile', authenticate, async (req, res) => {
    // Fetch user data from Firestore
    const userRef = usersCollection.doc(req.userId);
    const userDoc = await userRef.get();
    if (!userDoc.exists) {
        return res.status(404).send('User not found');
    }
    res.send(userDoc.data());
});

// Protected route example using Firebase Admin SDK
app.get('/protected-route', (req, res) => {
  const idToken = req.headers.authorization; // Assuming token is sent in the Authorization header

  admin.auth().verifyIdToken(idToken)
    .then((decodedToken) => {
      const uid = decodedToken.uid;
      // User is authenticated, proceed with the request
      res.send('Welcome, authenticated user!');
    })
    .catch((error) => {
      // Handle errors
      res.status(401).send('Unauthorized');
    });
});

// Handle static pages
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/login.html');
});

app.get('/signup', (req, res) => {
    res.sendFile(__dirname + '/signup.html');
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}/`);
});
