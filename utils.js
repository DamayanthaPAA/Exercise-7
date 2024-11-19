import jwt from 'jsonwebtoken';
import {getUsers} from './database.js'

// Using the correct import syntax for JSON modules
import * as settings from './config.json' assert { type: "json" }
const limiterSettings = settings.default.rateLimiterSettings;

const sum = (a, b) => {
    return a + b;
}

const getLimiterWindow = () => {
    const window = Math.round(Date.now() / limiterSettings.windowIizeInMillis)
    return window
}

const rateLimiter = (user, res) => {
    const window = getLimiterWindow()
    //is this user moving to the next window?
    if (user.rateLimiting.window < window) {
        user.rateLimiting.window = window;
        user.rateLimiting.requestCounter = 1

        res.set('x-RateLimit-Remaining', limiterSettings.limit - 1)

    } else {
        //we are at the same window that we visited last time
        if (user.rateLimiting.requestCounter >= limiterSettings.limit) {
            res.set('X-RateLimit-Remaining', 0)
            res.status(429).end()
            return true
        } else {
            user.rateLimiting.requestCounter++
            res.set('X-RateLimit-Remaining', limiterSettings.limit - user.rateLimiting.requestCounter)
        }
    }

    return false
}

function verifyToken(req, res, next) {
    const bearer_token = req.header('Authorization');
    if (bearer_token && bearer_token.toLowerCase().startsWith('bearer ')) {
        const token = bearer_token.substring(7);
        try {
            const decodedToken = jwt.verify(token, 'my_secret_key');
            const now = Date.now() / 1000;
            console.log(decodedToken);
            const isValid = (decodedToken.exp - now) >= 0;
            if (isValid) {
                // Fixed the comparison operator from = to ===
                let users = getUsers().find(a => (a.username === decodedToken.username) && (a.token === token));
                if (users) {
                    // Fixed the parameter order in rateLimiter call
                    if (!rateLimiter(users, res)) {
                        next();
                    }
                } else {
                    res.status(401).json({ "error": "Unauthorized" });
                }
            } else {
                res.status(401).json({ "error": "Invalid token" });
            }
        } catch (err) {
            console.log(err);
            res.status(401).json({ "error": "Invalid token catch" });
        }
    } else {
        res.status(401).json({ "error": "Invalid token" });
    }
} 

export {
    sum,
    verifyToken
}