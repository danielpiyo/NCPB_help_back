// getting dependacies
const express = require('express');
const path = require('path');
const http = require('http');
const bodyParser = require('body-parser');
const cors = require('cors');

// API routes
const api = require('./routes/apiv1');
const app = express();

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

// pont static path to dist
app.use(express.static(path.join(__dirname, 'dist')));

// set api routes
app.use('/apiv1', api);

// catch all other routers and return to index
app.get('*', (req, res) => {
    // res.sendFile('localhost:4200')
    res.sendFile(path.join(__dirname, './wrong.html'));
});

// get port from environment and stroe in express
const port = process.env.PORT || '4000';
app.set('port', port);

// create http server
const server = http.createServer(app);

// server listens on provided port
server.listen(port, () => {
    console.log(`                                    **************          
                          ******************************************
        ****************************************************************************************   
                        ***********NCPB helpdesk API listens to port:${port} *************
     ****************************************************************************************
                        ******************************************`);
});