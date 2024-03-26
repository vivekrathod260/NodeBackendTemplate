const express = require('express');
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");

const { authenticate, hash } = require("./helper.js");

require("dotenv").config();

const app = express();

///////////////////////

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.json());

//////////////////////////////////////////////////////

const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./database.db', (err)=>{ if(err) console.log(err); else console.log('Connected'); });

db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username VARCHAR(50) NOT NULL,
        password VARCHAR(50) NOT NULL
    )
`);

////////////////////

app.get('/', (req, res) => {   
    res.send("Hello home");
});

app.get('/login/:username/:password', (req, res) => {

    db.all('SELECT * FROM users where username=? and password=? ',[req.params.username, hash(req.params.password, process.env.SALT)], (err, rows)=>{
        if(err)
        {
            res.status(401).send('error !');
            console.log(err);
            return;
        }
        else if(rows.length == 0)
        {
            res.status(401).send('Invalid username or password');
            console.log('Invalid credentials !');
            return; 
        }
        else
        {
            var data = { usename:req.params.username, datetime: new Date() }

            const token = jwt.sign(data, process.env.KEY, { expiresIn: '1h' })
            res.cookie('myCookie', token, { maxAge: 900000, httpOnly: true });

            res.send("hello "+rows[0].username);
        }
    })
});

app.get('/register/:username/:password', (req, res) => {
    
    db.all(`SELECT * FROM users where username=?`,[req.params.username], (err, rows)=>{
        if(err)
        {
            res.status(401).send('error !');
            console.log(err);
            return;
        }
        else if(rows.length != 0)
        {
            res.status(401).send('user exists !');
            console.log('user exists !');
            return; 
        }
        else
        {
            db.run('INSERT INTO users (username, password) VALUES (?, ?)',[req.params.username, hash(req.params.password, process.env.SALT)], (err)=>{
                if(err)
                {
                    res.status(401).send('error !');
                    console.log(err);
                    return;
                }
                
                res.send("registered");
                console.log("registered");
            })
        }
    })
});

app.get('/protected', authenticate, (req, res) => {
    res.send('This is a protected route : hello '+req.username);
});

app.get('/logout', (req, res) => {
    res.clearCookie('myCookie');
    res.send('Logged out successfully');
});



app.listen(3000, () => {
    console.log('Server is listening on port 3000');
});
