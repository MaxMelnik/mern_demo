const express = require('express');
const config = require('config');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const app = express();

//app.use(bodyParser.urlencoded({ extended: true }));
//app.use(bodyParser.json());
app.use(express.json());

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
            () => console.log(`Server has been started on port ${PORT}...`)
        );
    } catch (e) {
        console.log('Server Error:', e.message);
        process.exit(1);
    }
}

start();

