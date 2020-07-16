const express = require('express');
const router = express.Router();
const bodyParser = require('body-parser');
const mysql = require('mysql');
const bcrypt = require('bcrypt-nodejs');
const jwt = require('jsonwebtoken');
const config = require(__dirname + '/config.js');
const localconf = require(__dirname + '/localconf.js');
const ActiveDirectory = require('activedirectory2');

// Use body parser to parse JSON body
router.use(bodyParser.json());
const connAttrs = mysql.createConnection(config.connection);

router.get('/', function (req, res) {
    res.sendfile('/')
});

// login
router.post('/signin', function (req, res) {

    // Initialize
    var signInconfig = {
        url: localconf.url,
        baseDN: localconf.baseDN,
        username: req.body.username,
        password: req.body.password
    }
    var ad = new ActiveDirectory(signInconfig);
    // Authenticate
    ad.authenticate(signInconfig.username, signInconfig.password, function (err, auth) {
        if (err) {
            console.log('ERROR: ' + JSON.stringify(err));
            res.status(401).send({
                message: 'Wrong Username or Password. please Try Again .'
            });
            return;
        }
        if (auth) {

            user = {
                username: signInconfig.username,
                code: 101
            }
            res.status(200).json({
                user : {
                    username: signInconfig.username,
                    code: 101
                },
                token: jwt.sign(user, config.jwtSecretKey, {
                    expiresIn: 60 * 60 * 24
                }) //EXPIRES IN ONE DAY,
            });
            console.log(`Authenticated! with username ${signInconfig.username}`);
        }
        else {
            res.status(500).send({
                message: 'Network Problem. please Try Again Latter .'
            });
            console.log('Authentication failed!');
        }
    });

});

// login
router.post('/signinIcto', function (req, res) {

    let user1 = {
        email: req.body.email,
        password: req.body.password
    }
    if (!user1) {
        return res.status(400).send({
            error: true,
            message: 'Please provide login details'
        });
    }
    connAttrs.query('SELECT * FROM system_users where email=?', user1.email, function (error, result) {
        if (error || result < 1) {
            res.set('Content-Type', 'application/json');
            var status = error ? 500 : 404;
            res.status(status).send(JSON.stringify({
                status: status,
                message: error ? "Error getting the that email" : "Email you have entered is Incorrect. Kindly Try Again. or Contact systemadmin",
                detailed_message: error ? error.message : ""
            }));
            console.log('========= You have Got an error ================ for this User: ' + user1.email);
            return (error);
        } else {
            user = result[0];


            bcrypt.compare(req.body.password, user.password, function (error, pwMatch) {
                var payload;
                if (error) {
                    return (error);
                }
                if (!pwMatch) {
                    res.status(401).send({
                        message: 'Wrong Password. please Try Again .'
                    });
                    return;
                }
                payload = {
                    sub: user.email,
                    user_id: user.id,
                    role: user.role,
                    region: user.rig_id
                };

                res.status(200).json({
                    user: {
                        username: user.username,
                        role: user.role
                    },
                    token: jwt.sign(payload, config.jwtSecretKey, {
                        expiresIn: 60 * 60 * 24
                    }) //EXPIRES IN ONE DAY,
                });
            });
        }

    });

});


// register
router.post('/register', function post(req, res, next) { // 

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }

        var user = {
            created_by: decoded.username,
            username: req.body.username,
            email: req.body.email,
            region: req.body.region,
            deport: req.body.deport,
            role: req.body.role
        };
        var unhashedPassword = req.body.password;
        bcrypt.genSalt(10, function (err, salt) {
            if (err) {
                return next(err);
            }
            // console.log(password);
            bcrypt.hash(unhashedPassword, salt, null, function (err, hash) {
                if (err) {
                    return next(err);
                }
                // console.log(hash);
                user.hashedPassword = hash;

                connAttrs.query(

                    'SELECT * FROM system_users where email=?', user.email, function (error, result) {
                        if (error || result.length > 0) {
                            res.set('Content-Type', 'application/json');
                            var status = error ? 500 : 404;
                            res.status(status).send(JSON.stringify({
                                status: status,
                                message: error ? "Error getting the server" : "Email you have entered is already taken.",
                                detailed_message: error ? error.message : `If user with this ${user.email} is nolonger with you please remove his details from the system`
                            }));
                            console.log("error occored");
                            return (error);
                        }
                        connAttrs.query("INSERT INTO system_users SET ? ", {
                            role: user.role,
                            email: user.email,
                            password: user.hashedPassword,
                            created_by: user.created_by,
                            rig_id: user.region,
                            username: user.username,
                            depo_id: user.deport
                        }, function (error, results) {
                            if (error) {
                                res.set('Content-Type', 'application/json');
                                res.status(500).send(JSON.stringify({
                                    status: 500,
                                    message: "Error Posting your details",
                                    detailed_message: error.message
                                }));
                            } else {
                                console.log(`${user.role}: ${user.email}, succesfully added by: ${user.created_by} on ${new Date()}`);
                                return res.contentType('application/json').status(201).send(JSON.stringify(results));
                            }
                        })
                    })
            })
        })
    })
});

// Adding new Department
router.post('/newDepartment', function (req, res) {
    var newDepartment = {       
        dep_name: req.body.dep_name,
        department_incharge: req.body.department_incharge
    }
    // token
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        connAttrs.query("INSERT INTO DEPARTMENTS SET ? ", {           
            dep_name: newDepartment.dep_name,
            department_incharge: newDepartment.department_incharge            
        }, function (error, results) {
            if (error) {
                res.set('Content-Type', 'application/json');
                res.status(500).send(JSON.stringify({
                    status: 500,
                    message: "Error Posting your Request",
                    detailed_message: error.message
                }));
            } else {
                console.log(`${decoded.username}, succesfully posted New Department on ${new Date()}`);
                return res.contentType('application/json').status(201).send(JSON.stringify(results));
            }
        });

    });
});

// Adding new category
router.post('/newCategory', function (req, res) {
    var newCategory = {       
        cat_name: req.body.cat_name,
        details: req.body.details
    }
    // token
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        connAttrs.query("INSERT INTO CATEGORIES SET ? ", {           
            cat_name: newCategory.cat_name,
            details: newCategory.details            
        }, function (error, results) {
            if (error) {
                res.set('Content-Type', 'application/json');
                res.status(500).send(JSON.stringify({
                    status: 500,
                    message: "Error Posting your Request",
                    detailed_message: error.message
                }));
            } else {
                console.log(`${decoded.username}, succesfully posted New Categpory on ${new Date()}`);
                return res.contentType('application/json').status(201).send(JSON.stringify(results));
            }
        });

    });
});

// Adding new Region
router.post('/newRegion', function (req, res) {
    var newRegion = {       
        rig_name: req.body.rig_name,
        rig_incharge: req.body.rig_incharge
    }
    // token
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        connAttrs.query("INSERT INTO REGIONS SET ? ", {           
            rig_name: newRegion.rig_name,
            rig_incharge: newRegion.rig_incharge            
        }, function (error, results) {
            if (error) {
                res.set('Content-Type', 'application/json');
                res.status(500).send(JSON.stringify({
                    status: 500,
                    message: "Error Posting your Request",
                    detailed_message: error.message
                }));
            } else {
                console.log(`${decoded.username}, succesfully posted New REGION on ${new Date()}`);
                return res.contentType('application/json').status(201).send(JSON.stringify(results));
            }
        });

    });
});


// Raising complain
router.post('/newRequest', function (req, res) {
    var newRequest = {
        category: req.body.category,
        desc: req.body.desc,
        department: req.body.department,
        deport: req.body.deport,
        region: req.body.region
    }
    // token
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        connAttrs.query("INSERT INTO REQUESTS SET ? ", {
            req_cat: newRequest.category,
            req_dept: newRequest.department,
            req_rig: newRequest.region,
            req_depo: newRequest.deport,
            req_desc: newRequest.desc,
            user_name: decoded.username,
            req_time: new Date()
        }, function (error, results) {
            if (error) {
                res.set('Content-Type', 'application/json');
                res.status(500).send(JSON.stringify({
                    status: 500,
                    message: "Error Posting your Request",
                    detailed_message: error.message
                }));
            } else {
                console.log(`${decoded.username}, succesfully posted a request on : ${newRequest.req_cat} on ${new Date()}`);
                return res.contentType('application/json').status(201).send(JSON.stringify(results));
            }
        });

    });
});

// pulling icto users to assign
router.post('/getIcto', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT email, rig_id, depo_id, role FROM system_users WHERE rig_id =?";
        connAttrs.query(sql, decoded.region, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found",
                    detailed_message: error ? error.message : "Sorry there are no Records Found set."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`ICTO pull released by ${decoded.sub} on ${new Date()}`);
        });
    });
});

// Get all ICTO USERS
router.post('/users', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM vw_icto_users order by id desc";
        connAttrs.query(sql, decoded.region, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found",
                    detailed_message: error ? error.message : "Sorry there are no Records Found set."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`ICTO pull released by ${decoded.sub} on ${new Date()}`);
        });
    });
});



// assign request
router.post('/assignRequest', function (req, res) {
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        } else {
            console.log('sub', decoded.sub)
            let requstsToAssign = {
                req_assigned_yn: 'Y',
                req_status: 'Assigned',
                req_assiged_by: decoded.username,
                req_assigned_to: req.body.username,
                req_assigned_at: new Date(),
                req_id: req.body.req_id
            }

            if (!requstsToAssign) {
                return res.status(400).send({
                    error: true,
                    message: 'Please provide details to send'
                });
            }
            let sql = "UPDATE requests SET req_status=?, req_assigned_yn=?, req_assiged_by=?, req_assigned_to = ?, req_assigned_at=? WHERE req_closed_yn= 'N' and req_id=?"
            connAttrs.query(sql, [requstsToAssign.req_status, requstsToAssign.req_assigned_yn, requstsToAssign.req_assiged_by,
            requstsToAssign.req_assigned_to, requstsToAssign.req_assigned_at, requstsToAssign.req_id],
                function (error, results) {
                    if (error) {
                        res.set('Content-Type', 'application/json');
                        res.status(500).send(JSON.stringify({
                            status: 500,
                            message: "Error Updating your details",
                            detailed_message: error.message
                        }));
                    } else {
                        return res.contentType('application/json').status(201).send(JSON.stringify(results));
                    }
                })

            console.log("=========================================Post:/Request Assigned Released=========================")

        }
    })
})

// Escalate request
router.post('/escalateRequest', function (req, res) {
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        } else {
            console.log('sub', decoded.sub)
            let requstsToEscalate = {
                req_escalated_yn: 'Y',
                req_status: 'Escalated',
                req_escalated_by: decoded.username,
                req_escalated_to: req.body.icto_name,
                req_escalated_at: new Date(),
                req_id: req_id
            }

            if (!requstsToEscalate) {
                return res.status(400).send({
                    error: true,
                    message: 'Please provide details to send'
                });
            }
            let sql = "UPDATE requests SET req_status=?, req_escalated_yn=?, req_escalated_by=?, req_escalated_to = ?, req_escalated_at=? WHERE req_closed_yn= 'N' and req_id=?"
            connAttrs.query(sql, [requstsToEscalate.req_status, requstsToEscalate.req_escalated_yn, requstsToEscalate.req_escalated_by,
            requstsToEscalate.req_escalated_to, requstsToEscalate.req_escalated_at, requstsToEscalate.req_id],
                function (error, results) {
                    if (error) {
                        res.set('Content-Type', 'application/json');
                        res.status(500).send(JSON.stringify({
                            status: 500,
                            message: "Error Updating your details",
                            detailed_message: error.message
                        }));
                    } else {
                        return res.contentType('application/json').status(201).send(JSON.stringify(results));
                    }
                })

            console.log("=========================================Post:/Request Escalation Released=========================");

        }
    })
})


// close request
router.post('/closeRequest', function (req, res) {
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        } else {
            console.log('sub', decoded.sub)
            let requstsToClose = {
                req_closed_yn: 'Y',
                req_status: 'Closed',
                req_closed_by: decoded.username,
                req_closed_at: new Date(),
                req_id: req.body.req_id
            }

            if (!requstsToClose) {
                return res.status(400).send({
                    error: true,
                    message: 'Please provide details to send'
                });
            }
            let sql = "UPDATE requests SET req_status=?, req_closed_yn=?, req_closed_by=?, req_closed_at=? WHERE req_id=?"
            connAttrs.query(sql, [requstsToClose.req_status, requstsToClose.req_closed_yn, requstsToClose.req_closed_by,
            requstsToClose.req_closed_at, requstsToClose.req_id],
                function (error, results) {
                    if (error) {
                        res.set('Content-Type', 'application/json');
                        res.status(500).send(JSON.stringify({
                            status: 500,
                            message: "Error Updating your details",
                            detailed_message: error.message
                        }));
                    } else {
                        return res.contentType('application/json').status(201).send(JSON.stringify(results));
                    }
                })

            console.log("=========================================Post:/Request Closed Released=========================");

        }
    })
})


// Delete request
router.post('/deleteRequest', function (req, res) {
    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        } else {
            console.log('sub', decoded.sub)
            let requstsToDelete = {
                req_deleted_yn: 'Y',
                req_status: 'Deleted',
                req_deleted_by: decoded.username,
                req_deleted_at: new Date(),
                req_id: req_id
            }

            if (!requstsToDelete) {
                return res.status(400).send({
                    error: true,
                    message: 'Please provide details to send'
                });
            }
            let sql = "UPDATE requests SET req_status=?, req_deleted_yn=?, req_deleted_by=?, req_deleted_at=? WHERE req_id=?"
            connAttrs.query(sql, [requstsToDelete.req_status, requstsToDelete.req_deleted_yn, requstsToDelete.req_deleted_by,
            requstsToDelete.req_deleted_at, requstsToDelete.req_id],
                function (error, results) {
                    if (error) {
                        res.set('Content-Type', 'application/json');
                        res.status(500).send(JSON.stringify({
                            status: 500,
                            message: "Error Updating your details",
                            detailed_message: error.message
                        }));
                    } else {
                        return res.contentType('application/json').status(201).send(JSON.stringify(results));
                    }
                })

            console.log("=========================================Post:/Request Deleted Released=========================");

        }
    })
})


// pulling Open request
router.post('/openRequests', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM VW_ALL_REQUEST where status='Open'";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Requests found",
                    detailed_message: error ? error.message : "Sorry there are no Requests set."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`Open Request selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// pulling Closed request
router.post('/closedRequests', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM VW_ALL_REQUEST where status='Closed'";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Requests found",
                    detailed_message: error ? error.message : "Sorry there are no Requests set."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`Closed Request selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});


// pulling Assigned request
router.post('/assignedRequests', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM VW_ALL_REQUEST where status='Assigned'";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Requests found",
                    detailed_message: error ? error.message : "Sorry there are no Requests set."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`Assigned Request selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// pulling Escalated request
router.post('/escalatedRequests', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM VW_ALL_REQUEST where status='Escalated'";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Requests found",
                    detailed_message: error ? error.message : "Sorry there are no Requests set."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`Escalated Request selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// pulling Deleted request
router.post('/deletedRequests', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM VW_ALL_REQUEST where status='Deleted'";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Requests found",
                    detailed_message: error ? error.message : "Sorry there are no Requests set."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`Deleted Request selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// pulling All request
router.post('/allRequests', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM VW_ALL_REQUEST where status !='Deleted'";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Requests found",
                    detailed_message: error ? error.message : "Sorry there are no Requests set."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All Request selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// pulling My request
router.post('/myRequests', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM VW_ALL_REQUEST where requestUsername=? AND deleted ='N'";
        connAttrs.query(sql, decoded.username, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Requests found",
                    detailed_message: error ? error.message : "Sorry there are no Requests set."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All my Request selection Released succesfullly by ${decoded.username} on ${new Date()}`);
        });
    });
});

// REQUEST REPORTS , DAILY, WEEKLY, MONTHLY
router.post('/ictoRequestDaily', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM requests WHERE req_closed_by =? AND DATE_FORMAT(req_closed_at, '%Y-%m-%d') = curdate() AND req_deleted_yn ='N' ORDER BY DATE_FORMAT(req_closed_at, '%Y-%m-%d') DESC";
        connAttrs.query(sql,decoded.username, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found Yet",
                    detailed_message: error ? error.message : "Sorry there are no Records Found."
                }));
                return (error);
            }


            res.contentType('application/json').status(200).send(JSON.stringify(results));
            
        });
    });
});

// USER REPORTS  WEEKLY
router.post('/ictoRequestWeekly', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM requests WHERE req_closed_by = ? AND req_closed_at <= adddate(curdate(), INTERVAL 7-DAYOFWEEK(curdate()) DAY) AND req_closed_at >= adddate(curdate(), INTERVAL 1-DAYOFWEEK(curdate()) DAY) AND req_deleted_yn ='N' ORDER BY DATE_FORMAT(req_closed_at, '%Y-%m-%d') DESC";
        connAttrs.query(sql,decoded.username, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found Yet",
                    detailed_message: error ? error.message : "Sorry there are no Records Found."
                }));
                return (error);
            }


            res.contentType('application/json').status(200).send(JSON.stringify(results));
            
        });
    });
});

// USER REPORTS  MONTHLY
router.post('/ictoRequestMonthly', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM requests WHERE req_closed_by =? AND req_closed_at <= LAST_DAY(curdate()) AND req_closed_at >= date_add(date_add(LAST_DAY(curdate()),interval 1 DAY),interval -1 MONTH) AND req_deleted_yn ='N' ORDER BY DATE_FORMAT(req_closed_at, '%Y-%m-%d') DESC";
        connAttrs.query(sql,decoded.username, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found Yet",
                    detailed_message: error ? error.message : "Sorry there are no Records Found."
                }));
                return (error);
            }
            res.contentType('application/json').status(200).send(JSON.stringify(results));
            
        });
    });
});

// ICTO custom report
router.post('/ictoRequestCustomReport', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM requests WHERE req_closed_by =? AND req_closed_at BETWEEN ? and ?  AND req_deleted_yn ='N' ORDER BY DATE_FORMAT(req_closed_at, '%Y-%m-%d') DESC";
        connAttrs.query(sql,[decoded.username, req.body.start_date, req.body.end_date], function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found Yet",
                    detailed_message: error ? error.message : "Sorry there are no Records Found."
                }));
                return (error);
            }
            res.contentType('application/json').status(200).send(JSON.stringify(results));
            
        });
    });
});


//ADMIN custom REport
router.post('/requestCustomReport', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM requests WHERE req_closed_at BETWEEN ? and ?  and req_deleted_yn ='N' ORDER BY DATE_FORMAT(req_closed_at, '%Y-%m-%d') DESC";
        connAttrs.query(sql,[req.body.start_date, req.body.end_date], function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found Yet",
                    detailed_message: error ? error.message : "Sorry there are no Records Found."
                }));
                return (error);
            }
            res.contentType('application/json').status(200).send(JSON.stringify(results));
            
        });
    });
});

// Admin All reports
router.post('/requestAdminReport', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM requests where req_deleted_yn ='N' ORDER BY DATE_FORMAT(req_closed_at, '%Y-%m-%d') DESC";
        connAttrs.query(sql,[req.body.start_date, req.body.end_date], function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found Yet",
                    detailed_message: error ? error.message : "Sorry there are no Records Found."
                }));
                return (error);
            }
            res.contentType('application/json').status(200).send(JSON.stringify(results));
            
        });
    });
});

// get categories
router.post('/categories', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * from categories order by cat_id";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found",
                    detailed_message: error ? error.message : "Sorry there are no Records Found set."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`Category pull released by ${decoded.sub} on ${new Date()}`);
        });
    });
});

// get Departments
router.post('/departments', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * from departments order by dep_id";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found",
                    detailed_message: error ? error.message : "Sorry there are no Records Found set."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`Department pull released by ${decoded.sub} on ${new Date()}`);
        });
    });
});

// get regions
router.post('/regions', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * from regions order by rig_id";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found",
                    detailed_message: error ? error.message : "Sorry there are no Records Found set."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`Region pull released by ${decoded.sub} on ${new Date()}`);
        });
    });
});

// get deport
router.post('/deports', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * from deports where depo_rig=? order by depo_id";
        connAttrs.query(sql, req.body.region, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Records found",
                    detailed_message: error ? error.message : "Sorry there are no Records Found set."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`Deports pull released by ${decoded.sub} on ${new Date()}`);
        });
    });
});

/*  **************************************************************************************
************************************** Pulling category report
*************************************
*/
router.post('/categoryReport', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM vw_category_req";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No report found",
                    detailed_message: error ? error.message : "Sorry there are no reports."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All category request selection Released succesfullly by ${decoded.sub} on ${new Date()}`);
        });
    });
});

/*  **************************************************************************************
************************************** Pulling Monthly category report
*************************************
*/
router.post('/categoryMonthReport', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "SELECT * FROM vw_category_req_month";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No report found",
                    detailed_message: error ? error.message : "Sorry there are no reports."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All category request selection Released succesfullly by ${decoded.sub} on ${new Date()}`);
        });
    });
});


/*  **************************************************************************************
************************************** Total Reuests
*************************************
*/
router.post('/totalRequests', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "select count(*) total_requests FROM requests WHERE DATE_FORMAT(req_time, '%Y-%m-%d') = curdate()";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Requests found",
                    detailed_message: error ? error.message : "Sorry there are no Requests."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All Total Daily Request request selection Released succesfullly by ${decoded.sub} on ${new Date()}`);
        });
    });
});

/*  **************************************************************************************
************************************** Open Reuests
*************************************
*/
router.post('/totalOpen', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "select count(*) total_open FROM requests WHERE req_status='Open' and DATE_FORMAT(req_time, '%Y-%m-%d') = curdate()";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Open Request found",
                    detailed_message: error ? error.message : "Sorry there are no Open Request."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All Open Daily Request request selection Released succesfullly by ${decoded.sub} on ${new Date()}`);
        });
    });
});


/*  **************************************************************************************
************************************** Assigned Reuests
*************************************
*/
router.post('/totalAssigned', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "select count(*) total_assigned FROM requests WHERE req_status='Assigned' and DATE_FORMAT(req_assigned_at, '%Y-%m-%d') = curdate()";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Assigned Request found",
                    detailed_message: error ? error.message : "Sorry there are no Assigned Request."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All Assigned Daily Request request selection Released succesfullly by ${decoded.sub} on ${new Date()}`);
        });
    });
});



/*  **************************************************************************************
************************************** Escalated Reuests
*************************************
*/
router.post('/totalEscalated', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "select count(*) total_escalated FROM requests WHERE req_status='Escalated' and DATE_FORMAT(req_escalated_at, '%Y-%m-%d') = curdate()";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Escalated Request found",
                    detailed_message: error ? error.message : "Sorry there are no Escalated Request."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All Escalated Daily Request request selection Released succesfullly by ${decoded.sub} on ${new Date()}`);
        });
    });
});



/*  **************************************************************************************
************************************** Closed Reuests
*************************************
*/
router.post('/totalClosed', function (req, res) {

    var token = req.body.token;
    if (!token) return res.status(401).send({
        auth: false,
        message: 'No token provided.'
    });

    jwt.verify(token, config.jwtSecretKey, function (err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Sorry Your Token is not genuine. Failed to authenticate token.'
            });
        }
        var sql = "select count(*) total_closed FROM requests WHERE req_status='Closed' and DATE_FORMAT(req_closed_at, '%Y-%m-%d') = curdate()";
        connAttrs.query(sql, function (error, results) {
            if (error || results.length < 1) {
                res.set('Content-Type', 'application/json');
                var status = error ? 500 : 404;
                res.status(status).send(JSON.stringify({
                    status: status,
                    message: error ? "Error getting the server" : "No Closed Request found",
                    detailed_message: error ? error.message : "Sorry there are no Closed Request."
                }));
                return (error);
            }

            res.contentType('application/json').status(200).send(JSON.stringify(results));
            console.log(`All Closed Daily Request request selection Released succesfullly by ${decoded.sub} on ${new Date()}`);
        });
    });
});


module.exports = router;
