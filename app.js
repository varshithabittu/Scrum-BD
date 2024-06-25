const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const app = express();
const { v4: uuidv4 } = require('uuid');
const store = new session.MemoryStore();
const bcrypt = require('bcrypt');
require('dotenv').config();
const pool = require('./server/db');
const http = require('http');
const server = http.createServer(app);
const { Server } = require('socket.io');

const io = new Server(server, {
    cors: {
        origin: "http://localhost:3000",
        methods: ['GET', 'POST']
    }
});

app.post('/set_card_values', async (req, res) => {
    const { sessionid, cardValues } = req.body;
    try {
        const cardValuesJson = JSON.stringify(cardValues);
        await pool.query(
            `UPDATE voting 
             SET card_values = $2 
             WHERE session_id = $1`,
            [sessionid, cardValuesJson]
        );
        res.status(200).send('Card values updated');
    } catch (error) {
        console.error('Error setting card values:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/get_card_values/:sessionid', async (req, res) => {
    const { sessionid } = req.params;
    try {
        const result = await pool.query('SELECT card_values FROM voting WHERE session_id = $1 LIMIT 1', [sessionid]);
        if (result.rows.length > 0) {
            res.status(200).json(result.rows[0].card_values || '[]');
        } else {
            res.status(404).send('Session not found');
        }
    } catch (error) {
        console.error('Error fetching card values:', error);
        res.status(500).send('Internal Server Error');
    }
});
io.on("connection", (socket) => {
    socket.on('join_session', async ({ sessionid, username }) => {
        console.log(`User ${username} joined session: ${sessionid}`);
        const cardValuesQuery = 'SELECT card_values FROM voting WHERE session_id = $1 LIMIT 1;';
        const votersQuery = 'SELECT user_name, vote, votes_visible, average_vote, is_moderator FROM voting WHERE session_id = $1;'; // Adjust query as per your actual voters table structure

        try {
            const cardValuesResult = await pool.query(cardValuesQuery, [sessionid]);
            const votersResult = await pool.query(votersQuery, [sessionid]);

            // Join the session room
            socket.join(sessionid);

            // Emit card values to the user
            if (cardValuesResult.rows.length > 0) {
                const cardValues = cardValuesResult.rows[0].card_values;
                try {
                    const parsedCardValues = JSON.parse(cardValues || '[]');
                    socket.emit('card_values', parsedCardValues);
                } catch (parseError) {
                    console.error('Error parsing card values:', parseError);
                }
            }

            // Emit voters to all users in the session room
            io.in(sessionid).emit("voters", votersResult.rows);
        } catch (err) {
            console.error(err);
        }
    });

    socket.on('update_card_values', async ({ sessionid, cardValues }) => {
        try {
            const cardValuesJson = JSON.stringify(cardValues);
            await pool.query(
                `UPDATE voting 
                 SET card_values = $2 
                 WHERE session_id = $1`,
                [sessionid, cardValuesJson]
            );
            io.to(sessionid).emit('card_values', cardValues);
        } catch (err) {
            console.error(err);
        }
    });

    socket.on("submit_vote", async ({ sessionid, username, vote,isModarator }) => {
        console.log(`Vote received: SessionID: ${sessionid}, Username: ${username}, Vote: ${vote},Modarator:${isModarator}`);
        const query = 'UPDATE voting SET vote = $1 WHERE session_id = $2 AND user_name = $3 RETURNING *;';
        const values = [vote, sessionid, username];
        try {
            const result = await pool.query(query, values);
            if (result.rowCount === 1) {
                const updatedResult = await pool.query('SELECT * FROM voting WHERE session_id = $1;', [sessionid]);
                io.in(sessionid).emit("voters", updatedResult.rows);
            } else {
                console.log(`Vote update failed: ${username} in session ${sessionid}`);
            }
        } catch (err) {
            console.error(err);
        }
    });
    socket.on("toggle_votes", async ({ sessionid, visibility }) => {
        console.log(`Toggling votes visibility for session: ${sessionid} to ${visibility}`);
        const query = 'UPDATE voting SET votes_visible = $1 WHERE session_id = $2;';
        const values = [visibility, sessionid];
        try {
            await pool.query(query, values);
            io.in(sessionid).emit("toggle_votes", visibility);
        } catch (err) {
            console.error('Error toggling votes visibility:', err);
        }
    });

    socket.on("finalize_votes", async ({ sessionid }) => {
        console.log(`Finalizing votes for session: ${sessionid}`);
        const query = 'UPDATE voting SET is_vote_finalized = true WHERE session_id = $1;';
        try {
            await pool.query(query, [sessionid]);
            const average = await calculateAverageVotes(sessionid);
            io.in(sessionid).emit("average_votes", average);
        } catch (err) {
            console.error('Error finalizing votes:', err);
        }
    });
});

async function calculateAverageVotes(sessionid) {
    const query = 'SELECT AVG(vote::numeric) AS average_vote FROM voting WHERE session_id = $1 AND is_vote_finalized = true;';
    try {
        const result = await pool.query(query, [sessionid]);
        return result.rows[0].average_vote !== null ? parseFloat(result.rows[0].average_vote) : 0;
    } catch (err) {
        console.error('Error calculating average votes:', err);
        return 0;
    }
}

async function calculateAverageVotes(sessionid) {
    const query = 'SELECT AVG(vote::numeric) AS average_vote FROM voting WHERE session_id = $1 AND is_vote_finalized = true;';
    try {
        const result = await pool.query(query, [sessionid]);
        return result.rows[0].average_vote !== null ? parseFloat(result.rows[0].average_vote) : 0;
    } catch (err) {
        console.error('Error calculating average votes:', err);
        return 0;
    }
}



app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));

app.use(session({
    secret: 'f4z4gs$Gcg',
    resave: false,
    saveUninitialized: false,
    store,
    cookie: { maxAge: 300000, secure: false }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy((username, password, done) => {
    const query = 'SELECT * FROM users WHERE username = $1';
    pool.query(query, [username], async (err, result) => {
        if (err) {
            return done(err);
        }
        if (result.rows.length === 0) {
            return done(null, false, { message: 'Incorrect username.' });
        }
        const user = result.rows[0];
        try {
            const matchedPassword = await bcrypt.compare(password, user.password);
            if (!matchedPassword) {
                return done(null, false, { message: 'Incorrect password.' });
            }
            return done(null, user);
        } catch (bcryptError) {
            return done(bcryptError);
        }
    });
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
        const user = result.rows[0];
        done(null, user);
    } catch (err) {
        done(err);
    }
});

app.get('/public/*', (req, res) => {
    const filePath = path.join(__dirname, req.path);
    res.sendFile(filePath);
});

app.post('/login', passport.authenticate('local', {
    successRedirect: '/home',
    failureRedirect: '/loginpage'
}));

app.post("/signin", async (req, res) => {
    const { username, password, email } = req.body;
    const id = uuidv4();
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);

    const query = 'INSERT INTO users (id, username, password, email) VALUES ($1, $2, $3, $4)';
    const values = [id, username, hash, email];

    try {
        const result = await pool.query(query, values);
        console.log("Success");
        res.redirect("/loginpage");
    } catch (err) {
        console.error('Error querying the database:', err);
        res.status(500).send('Try using a different username, password, or email');
    }
});

app.post('/logout', function (req, res, next) {
    req.logout(function (err) {
        if (err) { return next(err); }
        res.send('/loginpage');
    });
});

app.get('/api/check-auth', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({ isAuthenticated: true });
    } else {
        res.json({ isAuthenticated: false });
    }
});

app.post('/session', async (req, res) => {
    const { sessionname, username } = req.body;
    const id = uuidv4();
    const query1 = 'INSERT INTO sessions (id, session_name, user_name, status, date, votes_visible) VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, $5)';
    const values1 = [id, sessionname, username, "active", false]; 
    const query2 = 'INSERT INTO voting (session_id, user_name, is_moderator) VALUES ($1, $2, $3);';
    const values2 = [id, username, true]; 

    try {
        const result1 = await pool.query(query1, values1);
        if (result1.rowCount === 1) {
            const result2 =  await pool.query(query2, values2);
            if (result2.rowCount === 1) {
                return res.redirect(`/voting/${id}`);
            } else {
                return res.status(500).send('Failed to join the session.');
            }
        } else {
            return res.status(404).send('Session not found.');
        }
    } catch (err) {
        console.error('Error inserting into the database:', err);
        return res.status(500).send("Error");
    }
});

app.post('/joinsession', async (req, res) => {
    const { sessionid, username } = req.body;
    const query = 'INSERT INTO voting (session_id, user_name) VALUES ($1, $2);';
    const values = [sessionid, username];
    try {
        const result = await pool.query(query, values);
        if (result.rowCount === 1) {
            return res.redirect(`/voting/${sessionid}`);
        } else {
            return res.status(500).send('Failed to join the session.');
        }
    } catch (err) {
        console.error('Error inserting into the database:', err);
        return res.status(500).send("Error");
    }
});

app.post('/toggle_votes_visibility', async (req, res) => {
    const { sessionid } = req.body;
    console.log(`Toggling vote visibility for session: ${sessionid}`);
    const query = 'UPDATE sessions SET votes_visible = TRUE WHERE id = $1 AND votes_visible = FALSE RETURNING votes_visible;';
    try {
        const result = await pool.query(query, [sessionid]);
        if (result.rowCount === 1) {
            io.in(sessionid).emit("toggle_votes", true);
            res.sendStatus(200);
        } else {
            console.log(`Votes visibility already shown for session: ${sessionid}`);
            res.status(400).send('Votes already visible');
        }
    } catch (err) {
        console.error('Error toggling vote visibility:', err);
        res.status(500).send('Internal server error');
    }
});
app.post('/finalize_votes', async (req, res) => {
    const { sessionid } = req.body;
    console.log(`Finalizing votes for session: ${sessionid}`);
    const query = 'UPDATE voting SET is_vote_finalized = true WHERE session_id = $1;';
    try {
        await pool.query(query, [sessionid]);
        const average = await calculateAverageVotes(sessionid);
        io.in(sessionid).emit("average_votes", average);
        res.sendStatus(200); 
    } catch (err) {
        console.error('Error finalizing votes:', err);
        res.status(500).send('Internal server error');
    }
});


const PORT = process.env.PORT || 4000;

server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
