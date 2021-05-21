const express = require('express');
const config = require('config');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.use('/api/auth', require('./routes/auth.routes'));

const PORT = config.get('port') || 5000;

async function start() {
    try {
        await mongoose.connect(config.get('mongoUri'), {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            useCreateIndex: true
        });
        app.listen(
            PORT,
            () => console.log(`Server has been started at port ${PORT}...`)
        );
    } catch (e) {
        console.log('Server Error:', e.message);
        process.exit(1);
    }
}

start();

