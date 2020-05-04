const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const app = express();
var path = require('path');
const port = 8080;

app.set('view engine', 'ejs');
app.use(bodyParser.raw({ type: 'application/x-www-form-urlencoded'}));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname + '/site/index.html'));
});

app.get('/auth-handler', (req, res) => {
  res.render('auth-handler', { post_body: ''});
});

app.post('/auth-handler', (req, res) => {
  res.render('auth-handler', { post_body: req.body});
});

app.use(express.static(__dirname + '/site'));

app.listen(port, () => 
  console.log(`Example app listening on port ${port}!`)
);