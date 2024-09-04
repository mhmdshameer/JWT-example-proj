import express from "express";
import jwt from "jsonwebtoken";

const app = express();
const port = 4000;

app.use(express.json());

const users = [
    {
        id: 1,
        username: "shameer",
        password: "shameer8864",
        isAdmin: true,
    },
    {
        id: 2,
        username: "sunduse",
        password: "sunduse7244",
        isAdmin: false,
    },
];

let refreshTokens = [];

// Generate Access Token
const generateAccessToken = (user) => {
    return jwt.sign(
        { id: user.id, isAdmin: user.isAdmin },
        "mySecretKey",
        { expiresIn: "15s" }
    );
};

// Generate Refresh Token
const generateRefreshToken = (user) => {
    const refreshToken = jwt.sign(
        { id: user.id, isAdmin: user.isAdmin },
        "myRefreshSecretKey"
    );
    refreshTokens.push(refreshToken);
    return refreshToken;
};

// Refresh Token Route
app.post("/api/refresh", (req, res) => {
    const refreshToken = req.body.token;

    if (!refreshToken) return res.status(401).json("You're not authenticated");
    if (!refreshTokens.includes(refreshToken)) {
        return res.status(403).json("Refresh token is not valid");
    }
    jwt.verify(refreshToken, "myRefreshSecretKey", (err, user) => {
        if (err) {
            return res.status(403).json("Refresh token is not valid");
        }
        refreshTokens = refreshTokens.filter((token) => token !== refreshToken);

        const newAccessToken = generateAccessToken(user);
        const newRefreshToken = generateRefreshToken(user);

        res.status(200).json({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
        });
    });
});

// Login Route
app.post("/login", (req, res) => {
    const user = users.find((u) => {
        return u.username === req.body.username && u.password === req.body.password;
    });

    if (user) {
        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);
        res.json({
            username: user.username,
            isAdmin: user.isAdmin,
            accessToken,
            refreshToken,
        });
    } else {
        res.status(400).json("Username or password incorrect");
    }
});

// Middleware to Verify Token
const verify = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(" ")[1];
        jwt.verify(token, "mySecretKey", (err, user) => {
            if (err) {
                return res.status(403).json("Token is not valid");
            }
            req.user = user;
            next();
        });
    } else {
        return res.status(401).json("You're not authenticated");
    }
};

// Delete User Route
app.delete("/api/users/:userId", verify, (req, res) => {
    if (req.params.userId == req.user.id || req.user.isAdmin) {
        res.status(200).json("User has been deleted");
    } else {
        res.status(403).json("You are not allowed to delete this user");
    }
});

app.post("/api/logout", verify,(req, res)=>{
    const refreshToken = req.body.token;
    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
    res.status(200).json("You logged out successfully.");
});

// Start Server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});


