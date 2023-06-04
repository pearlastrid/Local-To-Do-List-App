require('dotenv').config();
const express = require("express");
const mysql = require("mysql");
const session = require("express-session");
const mySQlStore = require("express-mysql-session")(session);
const bcrypt = require('bcryptjs');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const flash = require('connect-flash');

const app = express();
app.use(express.json());
app.use(express.urlencoded({
    extended: true
}));


app.use(express.static(__dirname + '/public/views'));
app.use(express.static(__dirname + '/public/error-pages'));

app.set('views', __dirname + '/public');
app.set('view engine', 'ejs');

var connectionPool = mysql.createPool({
    connectionLimit: 100,
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

const sessionStore = new mySQlStore({
    createDatabaseTable: false
}, connectionPool);

// wrapper function
function register(username, password, confirmPassword) {
    return new Promise((resolve, reject) => {
        if (password != confirmPassword) {
            reject(new Error("Passwords need to match."));
        }
        else {
            userExists(username).then((response) => {
                console.log(response);
                
                if (response) {
                    console.log("User already exists");
                    reject(new Error(`This user already exists.`));
                }
                else {
                    insertUser(username, password).then((response) => {
                        insertSettings(response.user_id).then(() => {
                            console.log("User successfully inserted");
                            resolve({
                                body: {
                                    message: `Successfully registered.`
                                }
                            });
                        }).catch((error) => {
                            reject(new Error(error.message));
                        });
                    }).catch((error) => {
                        reject(new Error(error.message));
                    });
                }
                
            }).catch((error) => {
                reject(new Error(error.message));
            });
        }
    });
}

function userExists(username) {
    return new Promise((resolve, reject) => {
        findUser(username).then((response) => {
            if (response.length > 0) {
                resolve(true);
            }
            else {
                resolve(false);
            }
        }).catch((error) => {
            reject(new Error(error.message));
        });
    });
    
    
}

function findUser(username) {
    console.log("inside find user");
    return new Promise((resolve, reject) => {
        connectionPool.getConnection((err, connection) => {
            if (err) {
                connection.release();
                reject(new Error(err.message));
            }
            else {
                connection.query("SELECT * FROM users WHERE USERNAME=?", username, function(error, results, fields) {
            
                    if (error) {
                        reject(new Error(error.message));
                    }
                    else {
                        resolve(results);
                    }

                    connection.release();
                });
            }
        });
    });
}

function insertUser(username, password) {
    return new Promise((resolve, reject) => {
        genPassword(password).then((response) => {
            const salt = response.salt;
            const hash = response.hash;

            connectionPool.getConnection((err, connection) => {
                if (err) {
                    connection.release();
                    reject(new Error(err.message));
                }
                else {
                    connection.query('INSERT INTO users (USERNAME, HASH, SALT, IS_ADMIN) VALUES (?, ?, ?, 0)', [username, hash, salt], function(error, results, fields) {
                        if (error) {
                            reject(new Error(error.message));
                        }
                        else {
                            resolve({
                                message: 'User successfully inserted',
                                user_id: results.insertId
                            });
                        }

                        connection.release();
                    });
                }
            });

        }).catch((error) => {
            reject(new Error(error.message));
        });
    });
}


async function genPassword(password) {

    let salt = await bcrypt.genSalt();
    let hash = await bcrypt.hash(password, salt);

    return {
        salt: salt,
        hash: hash
    };
    
}

function insertSettings(user_id) {
    return new Promise((resolve, reject) => {
        connectionPool.getConnection((err, connection) => {
            if (err) {
                connection.release();
                reject(new Error(err.message));
            }
            else {
                connection.query(`INSERT INTO settings (USER_ID, SHOW_DELETE_LIST_POPUP, FONT_FAMILY, THEME) VALUES (?, 1, "\'Trebuchet MS\'\, \'Lucida Sans Unicode\'\, \'Lucida Grande'\, \'Lucida Sans\'\, Arial\, sans-serif", "Standard")`, [user_id], function(error, results, fields) {
                    if (error) {
                        reject(new Error(error.message));
                    }
                    else {
                        resolve({
                            message: 'Setting successfully inserted',
                            setting_id: results.insertId
                        });
                    }

                    connection.release();
                });
            }
        });
    });
}

function verifyUser(username, password, callback) {
    console.log("inside verify user");
    findUser(username).then((response) => {
        if (response.length === 0) {
            return callback(null, false, {message: 'Incorrect username or password.'});
        }
        else {
            verifyPassword(password, response[0].SALT, response[0].HASH).then((verified) => {
                if (verified) {
                    const user = {
                        id: response[0].ID,
                        username: response[0].USERNAME,
                        hash: response[0].HASH,
                        salt: response[0].SALT
                    };

                    return callback(null, user);
                }
                else {
                    return callback(null, false, {message: 'Incorrect username or password.'});
                }
            }).catch((error) => {
                return callback(error);
            });
        }
    }).catch((error) => {
        return callback(error);
    });
}


async function verifyPassword(password, salt, hash) {
    console.log("inside verify password");
    const hashVerify = await bcrypt.hash(password, salt);
    return hash === hashVerify;
}


function isAuth(req, res, next) {
    if (req.isAuthenticated()) {
        next();
    }
    else {
        req.flash('error', 'You are not currently logged in. Please login first to access and edit your lists.');
        return res.status(401).sendFile(__dirname + '/public/error-pages/not-authorized.html');
    }
}


function parseUserToDos(results, delimInner, delimOuter) {
    return new Promise((resolve, reject) => {
        let parsedToDos = [];
        try {
            for (let i = 0; i < results.length; i++) {
                parsedToDos[i] = {};
                parsedToDos[i].ID = results[i].ID;
                parsedToDos[i].USER_ID = results[i].USER_ID;
                parsedToDos[i].NAME = results[i].NAME;

                if (results[i].listToDos) { // truthy statement
                    parsedToDos[i].listToDos = results[i].listToDos.split(delimOuter);
                    
                    for (let k = 0; k < parsedToDos[i].listToDos.length; k++) {
                        let listComponents = parsedToDos[i].listToDos[k].split(delimInner);
                        parsedToDos[i].listToDos[k] = {
                            'todo_id': listComponents[0],
                            'task': listComponents[1],
                            'is_done': listComponents[2]
                        };
                    }
                    
                }
                else {
                    parsedToDos[i].listToDos = [];
                }
            }
            resolve(parsedToDos);
        }
        catch(error) {
            reject(new Error(error.message));
        }
    });
    
}

function getUserToDos(user_id, delimInner, delimOuter) {
    return new Promise((resolve, reject) => {
        connectionPool.getConnection((err, connection) => {
            if (err) {
                connection.release();
                reject(new Error(err.message));
            }
            else {
                connection.query(`SELECT lists.ID, lists.USER_ID, lists.NAME, GROUP_CONCAT(CONCAT(todos.ID, '${delimInner}', todos.TASK, '${delimInner}', todos.IS_DONE) SEPARATOR '${delimOuter}')
                AS listToDos FROM lists LEFT JOIN todos ON lists.ID = todos.LIST_ID WHERE USER_ID=? GROUP BY lists.ID`, 
                [user_id], function(error, results, fields) {
                    if (error) {
                        reject(new Error(error.message));
                    }
                    else {
                        parseUserToDos(results, delimInner, delimOuter).then((response) => {
                            resolve(response);
                        }).catch((error) => {
                            reject(new Error(error.message));
                        });
                    }

                    connection.release();
                });
            }
        });
    });
}


function addToDo(task, list_id) {
    return new Promise((resolve, reject) => {
        connectionPool.getConnection((err, connection) => {
            if (err) {
                connection.release();
                reject(new Error(err.message));
            }
            else {
                connection.query('INSERT INTO todos (TASK, IS_DONE, LIST_ID) VALUES (?, 0, ?)', [task, list_id], function(error, results, fields) {
                    if (error) {
                        reject(new Error(error.message));
                    }
                    else {
                        resolve({
                            body: {
                                message: 'To Do inserted successfully.',
                                task: task,
                                id: results.insertId
                            }
                        })
                    }

                    connection.release();
                });
            }
        });
    });
}

function removeToDo(todo_id) {
    return new Promise((resolve, reject) => {
        connectionPool.getConnection((err, connection) => {
            if (err) {
                connection.release();
                reject(new Error(err.message));
            }
            else {
                connection.query('DELETE FROM todos WHERE ID=?', [todo_id], function(error, results, fields) {
                    if (error) {
                        reject(new Error(error.message));
                    }
                    else {
                        resolve({
                            body: {
                                message: 'ToDo successfully deleted',
                                id: todo_id
                            }
                        })
                    }

                    connection.release();
                });
            }
        });
    });
}

// wrapper function
function addList(name, user_id) {
    return new Promise((resolve, reject) => {
        connectionPool.getConnection((err, connection) => {
            if (err) {
                connection.release();
                reject(new Error(err.message));
            }
            else {
                connection.query('INSERT INTO lists (NAME, USER_ID) VALUES (?, ?)', [name, user_id], function(error, results, fields) {
                    if (error) {
                        reject(new Error(error.message));
                    }
                    else {
                        resolve({
                            body: {
                                message: 'List sucessfully inserted.',
                                id: results.insertId
                            }
                        });
                    }

                    connection.release();
                });
            }
        });
    });
}

function deleteList(list_id) {
    return new Promise((resolve, reject) => {
        connectionPool.getConnection((err, connection) => {
            if (err) {
                connection.release();
                reject(new Error(err.message));
            }
            else {
                connection.query('DELETE FROM lists WHERE ID=?', [list_id], function(error, results, fields) {
                    if (error) {
                        reject(new Error(error.message));
                    }
                    else {
                        resolve({
                            body: {
                                message: 'List successfully deleted.',
                                id: list_id
                            }
                        })
                    }
        
                    connection.release();
                });
            }
        });
    });
}

function updateToDoCheckbox(todo_id, is_done) {
    return new Promise((resolve, reject) => {
        connectionPool.getConnection((err, connection) => {
            if (err) {
                connection.release();
                reject(new Error(err.message));
            }
            else {
                connection.query('UPDATE todos SET IS_DONE=? WHERE ID=?', [is_done, todo_id], function(error, results, fields) {
                    if (error) {
                        reject(new Error(error.message));
                    }
                    else {
                        resolve({
                            body: {
                                message: "ToDo checkbox successfully updated.",
                                id: todo_id
                            }
                        });
                    }

                    connection.release();
                });
            }
        });
        
    });
}

function updateListTitle(list_id, newTitle) {
    return new Promise((resolve, reject) => {
        connectionPool.getConnection((err, connection) => {
            if (err) {
                connection.release();
                reject(new Error(err.message));
            }
            else {
                connection.query('UPDATE lists SET NAME=? WHERE ID=?', [newTitle, list_id], function(error, results, fields) {
                    if (error) {
                        reject(new Error(error.message));
                    }
                    else {
                        resolve({
                            body: {
                                message: 'List title successfully updated.',
                                id: list_id
                            }
                        });
                    }

                    connection.release();
                });
            }
        });
    });
}

function getUserSettings(user_id) {
    return new Promise((resolve, reject) => {
        connectionPool.getConnection((err, connection) => {
            if (err) {
                connection.release();
                reject(new Error(err.message));
            }
            else {
                connection.query('SELECT * FROM settings WHERE USER_ID=?', [user_id], function(error, results, fields) {
                    if (error) {
                        reject(new Error(error.message));
                    }
                    else {
                        resolve(results[0]);
                    }

                    connection.release();
                });
            }
        });
    });
}

function changeUserDeleteListPopupPreference(user_id, show_popup) {
    return new Promise((resolve, reject) => {
        connectionPool.getConnection((err, connection) => {
            if (err) {
                connection.release();
                reject(new Error(err.message));
            }
            else {
                connection.query('UPDATE settings SET SHOW_DELETE_LIST_POPUP=? WHERE USER_ID=?', [show_popup, user_id], function(error, results, fields) {
                    if (error) {
                        reject(new Error(error.message));
                    }
                    else {
                        console.log('here');
                        resolve({
                            
                            body: {
                                message: 'User delete list popup preference successfully updated',
                                updated_show_popup: show_popup
                            }
                        });
                    }

                    connection.release();
                });
            }
        });
    });
}

function changeUserFont(user_id, new_font) {
    return new Promise((resolve, reject) => {
        connectionPool.getConnection((err, connection) => {
            if (err) {
                connection.release();
                reject(new Error(err.message));
            }
            else {
                connection.query('UPDATE settings SET FONT_FAMILY=? WHERE USER_ID=?', [new_font, user_id], function(error, results, fields) {
                    if (error) {
                        reject(new Error(error.message));
                    }
                    else {
                        resolve({
                            body: {
                                message: 'Font successfully updated.',
                                new_font: new_font
                            }
                        });
                    }

                    connection.release();
                });
            }
        });
    });
}

function changeUserTheme(user_id, new_theme) {
    return new Promise((resolve, reject) => {
        connectionPool.getConnection((err, connection) => {
            if (err) {
                connection.release();
                reject(new Error(err.message));
            }
            else {
                connection.query('UPDATE settings SET THEME=? WHERE USER_ID=?', [new_theme, user_id], function(error, results, fields) {
                    if (error) {
                        reject(new Error(error.message));
                    }
                    else {
                        resolve({
                            body: {
                                message: 'Theme successfully updated.',
                                new_theme: new_theme
                            }
                        });
                    }

                    connection.release();
                });
            }
        });
    });
}


/***************** PASSPORT.JS *************************/


const strategy = new LocalStrategy(verifyUser);
passport.use(strategy);


passport.serializeUser((user, callback) => {
    console.log("Inside serialize");
    console.log(user);
    process.nextTick(() => {
        return callback(null, {id: user.id, username: user.username});
    });
});

passport.deserializeUser((user, callback) => {
    console.log("Inside deserialize user");
    process.nextTick(() => {
        return callback(null, user);
    });
});


/************** MIDDLEWARE *********************/


app.use(session({
    key: 'myKey',
	secret: 'session_cookie_secret',
    name: 'mycookie',
	store: sessionStore,
	resave: false,
	saveUninitialized: true,
    cookie: {
        maxAge: 6000000
    }
}));


app.use(passport.initialize());
app.use(passport.session());
app.use(flash());


app.use((req, res, next) => {
    console.log(req.session);
    console.log(req.user);
    next();
});

/******************** ROUTES *******************/

app.get('/', (req, res, next) => {
    console.log(req.session.id);
    res.sendFile(__dirname + '/public/index.html');
})

app.get('/login', (req, res, next) => {
    let flashError = req.flash('error');
    let flashMessage = req.flash('message');
    res.render('login.ejs', {flashError: flashError, flashMessage: flashMessage});
});

app.get('/register', (req, res, next) => {
    res.sendFile(__dirname + '/public/register.html');
});

app.get('/landing', isAuth, (req, res, next) => {
    getUserToDos(req.user.id, '␜', '␝').then((response) => {
        console.dir(response, {depth: null});
        return res.render('landing.ejs', {flashError: [], userToDos: response, username: req.user.username});
    }).catch((error) => {
        return res.render('landing.ejs', {flashError: [error.message], userToDos: [], username: req.user.username});
    });
});


app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) {
            next(err);
        }
        req.flash('message', 'You are now logged out.');
        res.redirect('/login');
    });
});

app.get('/userSettings', isAuth, (req, res, next) => {
    getUserSettings(req.user.id).then((response) => {
        return res.send({
            success: true,
            body: response
        });
    }).catch((error) => {
        return res.send({
            success: false,
            body: {
                message: error.message
            }
        });
    });
});

app.get('/settings', isAuth, (req, res, next) => {
    getUserSettings(req.user.id).then((response) => {
        res.render('settings.ejs', {settings: response, flashError: [], username: req.user.username});
    }).catch((error) => {
        res.render('settings.ejs', {settings: [], flashError: [error.message], username: req.user.username});
    });
});

app.post('/login', passport.authenticate('local', {
    failureRedirect: '/login', 
    failureFlash: true, 
    successRedirect: '/landing'
}));

app.post('/register', (req, res) => {
    console.log(req.body);
    
    register(req.body.username, req.body.password, req.body.confirmPassword).then((response) => {
        console.log(response);
        
        return res.send({
            success: true,
            body: response.body
        });
        
    }).catch((error) => {
        return res.send({
            success: false,
            body: {
                message: error.message
            }
        });
    });
    
});

app.post('/addToDo', isAuth, (req, res) => {
    console.log(req.body);
    addToDo(req.body.task, req.body.list_id).then((response) => {
        return res.send({
            success: true,
            body: response.body
        })
    }).catch((error) => {
        return res.send({
            success: false,
            body: {
                message: error.message
            }
        })
    });
});


app.post('/addList', isAuth, (req, res) => {
    addList(req.body.name, req.user.id).then((response) => {
        return res.send({
            success: true,
            body: response.body
        });
    }).catch((error) => {
        return res.send({
            success: false,
            body: {
                message: error.message
            }
        });
    });
});

app.post('/deleteList', isAuth, (req, res) => {
    deleteList(req.body.id).then((response) => {
        return res.send({
            success: true,
            body: response.body
        });
    }).catch((error) => {
        return res.send({
            success: false,
            body: {
                message: error.message
            }
        });
    });
});

app.post('/removeToDo', isAuth, (req, res) => {
    console.log(req.body);
    removeToDo(req.body.id).then((response) => {
        return res.send({
            success: true,
            body: response.body
        });
    }).catch((error) => {
        return res.send({
            success: false,
            body: {
                message: error.message
            }
        });
    });
});

app.post('/updateToDoCheckbox', isAuth, (req, res) => {
    updateToDoCheckbox(req.body.id, req.body.is_done).then((response) => {
        return res.send({
            success: true,
            body: response.body
        });
    }).catch((error) => {
        return res.send({
            success: false,
            body: {
                message: error.message
            }
        });
    });
});

app.post('/updateListTitle', isAuth, (req, res) => {
    updateListTitle(req.body.id, req.body.newTitle).then((response) => {
        return res.send({
            success: true,
            body: response.body
        });
    }).catch((error) => {
        return res.send({
            success: false,
            body: {
                message: error.message
            }
        });
    });
});

app.post('/changeUserDeleteListPopupPreference', isAuth, (req, res) => {
    changeUserDeleteListPopupPreference(req.user.id, req.body.show_popup).then((response) => {
        return res.send({
            success: true,
            body: response.body
        });
    }).catch((error) => {
        return res.send({
            success: false,
            body: {
                message: error.message
            }
        });
    });
});

app.post('/changeFont', isAuth, (req, res) => {
    console.log(req.body);
    changeUserFont(req.user.id, req.body.font_family).then((response) => {
        return res.send({
            success: true,
            body: response.body
        });
    }).catch((error) => {
        return res.send({
            success: false,
            body: {
                message: error.message
            }
        });
    });
});

app.post('/changeTheme', isAuth, (req, res) => {
    console.log(req.body);
    changeUserTheme(req.user.id, req.body.theme).then((response) => {
        return res.send({
            success: true,
            body: response.body
        });
    }).catch((error) => {
        return res.send({
            success: false,
            body: {
                message: error.message
            }
        });
    });
});

app.use((req, res, next) => {
    res.status(404).sendFile(__dirname + '/public/error-pages/not-found.html');
})


app.listen(process.env.PORT);

