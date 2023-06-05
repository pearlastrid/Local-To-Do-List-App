/*
    Pearl Lin
    6.4.2023

    This program establishes the Express server hosting the To-Do List app
    and defines all of its routes and functionalities
*/

/*************** INITIALIZATION *******************/

// required all necessary dependencies
require('dotenv').config();
const express = require("express");
const mysql = require("mysql");
const session = require("express-session");
const mySQlStore = require("express-mysql-session")(session);
const bcrypt = require('bcryptjs');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const flash = require('connect-flash');

// initiate Express server and include middleware
const app = express();
app.use(express.json());
app.use(express.urlencoded({
    extended: true
}));

// include middleware for serving static files (css/images folder and error pages folder)
app.use(express.static(__dirname + '/public/views'));
app.use(express.static(__dirname + '/public/error-pages'));

// set view engine to ejs, allows us to use ejs in the public folder
app.set('views', __dirname + '/public');
app.set('view engine', 'ejs');

// declare connection pool to MySQL database
var connectionPool = mysql.createPool({
    connectionLimit: 100,
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

// initiailize the sessionStore, which will allow express-mysql-session to store session data into the database
const sessionStore = new mySQlStore({
    createDatabaseTable: false
}, connectionPool);


/******************** FUNCTIONS *********************/

// registers a user in the database and gives them default settings
function register(username, password, confirmPassword) {
    return new Promise((resolve, reject) => {
        if (password != confirmPassword) {
            reject(new Error("Passwords need to match."));
        }
        else {
            userExists(username).then((response) => {
                
                if (response) {
                    reject(new Error(`This user already exists.`));
                }
                else {
                    insertUser(username, password).then((response) => {
                        insertSettings(response.user_id).then(() => {
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

// check if a user already exists in the database
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

// retrieves user data by username, returns empty array if user does not exist 
function findUser(username) {
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

// inserts a user into the database
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

// generates a random salt to hash a user password, returns the salt and the hashed password
async function genPassword(password) {

    let salt = await bcrypt.genSalt();
    let hash = await bcrypt.hash(password, salt);

    return {
        salt: salt,
        hash: hash
    };
    
}

// inserts default settings into the database for a new user
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

// verifies the login credentials of a user
function verifyUser(username, password, callback) {
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

// compares the hash stored in the database to the hash generated with the user-entered password
async function verifyPassword(password, salt, hash) {
    const hashVerify = await bcrypt.hash(password, salt);
    return hash === hashVerify;
}

// middleware that checks if the user session is authenticated, sends a 401 unauthorized error and its error page if not
function isAuth(req, res, next) {
    if (req.isAuthenticated()) {
        next();
    }
    else {
        req.flash('error', 'You are not currently logged in. Please login first to access and edit your lists.');
        return res.status(401).sendFile(__dirname + '/public/error-pages/not-authorized.html');
    }
}

// parses the string of user To-Dos into an array of JSON objects 
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

// retrieves all the To-Dos of a user
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

// inserts a new To-Do into the database
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

// removes a To-Do from the database
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

// inserts a new list into the database
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

// deletes a list from the database
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

// updates the status of a To-Do checkbox (done or not?)
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

// updates the title of a list
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

// retrieves all the settings of a user
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

// updates a user's delete list popup preference
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

// updates a user's font setting
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

// updates a user's theme setting
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

// use the verifyUser function as a LocalStrategy for Passport.js authentication
const strategy = new LocalStrategy(verifyUser);
passport.use(strategy);

// serialize user into browser's session
passport.serializeUser((user, callback) => {
    process.nextTick(() => {
        return callback(null, {id: user.id, username: user.username});
    });
});

// retrieve user from browser's session
passport.deserializeUser((user, callback) => {
    process.nextTick(() => {
        return callback(null, user);
    });
});


/************** MIDDLEWARE *********************/

// stores session data into the database
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

// initializes Passport.js
app.use(passport.initialize());
// replaces session id in request object with user data pulled from deserialize user
app.use(passport.session());
// enable flash message system
app.use(flash());


/******************** ROUTES *******************/

// displays app home page
app.get('/', (req, res, next) => {
    res.sendFile(__dirname + '/public/index.html');
})

// renders login page
app.get('/login', (req, res, next) => {
    let flashError = req.flash('error');
    let flashMessage = req.flash('message');
    res.render('login.ejs', {flashError: flashError, flashMessage: flashMessage});
});

// displays register page
app.get('/register', (req, res, next) => {
    res.sendFile(__dirname + '/public/register.html');
});

// renders user landing page (protected route)
app.get('/landing', isAuth, (req, res, next) => {
    getUserToDos(req.user.id, '␜', '␝').then((response) => {
        return res.render('landing.ejs', {flashError: [], userToDos: response, username: req.user.username});
    }).catch((error) => {
        return res.render('landing.ejs', {flashError: [error.message], userToDos: [], username: req.user.username});
    });
});

// signs out the user, removes session and user data from request object
app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) {
            next(err);
        }
        req.flash('message', 'You are now logged out.');
        res.redirect('/login');
    });
});

// returns all settings of a user (protected route)
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

// renders the settings page (protected route)
app.get('/settings', isAuth, (req, res, next) => {
    getUserSettings(req.user.id).then((response) => {
        res.render('settings.ejs', {settings: response, flashError: [], username: req.user.username});
    }).catch((error) => {
        res.render('settings.ejs', {settings: [], flashError: [error.message], username: req.user.username});
    });
});

// renders the explore themes page (protected route)
app.get('/explore-themes', isAuth, (req, res, next) => {
    res.render('explore-themes.ejs', {username: req.user.username});
});

// endpoint to login, redirects to /landing on success, else redirects to /login with a flash error message on failure
app.post('/login', passport.authenticate('local', {
    failureRedirect: '/login', 
    failureFlash: true, 
    successRedirect: '/landing'
}));

// registers a user
app.post('/register', (req, res) => {
    
    register(req.body.username, req.body.password, req.body.confirmPassword).then((response) => {
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

// adds a To-Do to the database (protected route)
app.post('/addToDo', isAuth, (req, res) => {
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

// adds a list to the database (protected route)
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

// deletes a list from the database (protected route)
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

// removes a To-Do from the database (protected route)
app.post('/removeToDo', isAuth, (req, res) => {
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

// updates the status of a To-Do checkbox (protected route)
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

// updates the title of a list (protected route)
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

// changes the delete list popup preference in the user's settings (protected route)
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

// changes user's font setting (protected route)
app.post('/changeFont', isAuth, (req, res) => {
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

// changes user's theme setting (protected route)
app.post('/changeTheme', isAuth, (req, res) => {
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

// middleware to catch all other undefined routes, sends a 404 not found error and its error page
app.use((req, res, next) => {
    res.status(404).sendFile(__dirname + '/public/error-pages/not-found.html');
})

// app listens on the port
app.listen(process.env.PORT);

