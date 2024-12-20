import express from 'express';
import mysql from 'mysql';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt, { hash } from 'bcrypt';
import cookieParser from 'cookie-parser';
const app = express();
app.use(express.json());
app.use(cors({
  origin: ["http://localhost:3000"],
  methods: ["GET", "POST", "DELETE"],
  credentials: true
}));
app.use(cookieParser());

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'admin',
  database: 'finals_web',
})
const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json({ Error: "Unauthorized" })
  } else {
    jwt.verify(token, "jwtSecret", (err, decoded) => {
      if (err) {
        return res.json({ Error: "Unauthorized" })
      } else {
        req.email = decoded.email
        next()
      }
    })
  }
}
app.post('/updateResults', (req, res) => {
  const { id, name, email } = req.body;
  const query = 'INSERT INTO event_archive (id, name, email) VALUES (?, ?, ?)';
  db.query(query, [id, name, email], (err, result) => {
    if (err) {
      console.error('Error inserting into event_archive:', err);
      return res.json({ Status: 'Failed', Error: err });
    }
    res.json({ Status: 'Succeed' });
  });
});
app.get("/getProfile", verifyUser, (req, res) => {
  const sql = "SELECT * FROM comp_info WHERE email = ?"
  db.query(sql, [req.email], (err, result) => {
    if (err) return res.json({ Error: "Failed" })
    return res.json({ Status: "Succeed", Profile: result[0] })
  })
})
app.get("/results", (req, res) => {
  const sql = "SELECT * FROM event_archive"
  db.query(sql, (err, result) => {
    if (err) return res.json({ Error: "Failed" })
    return res.json({ Status: "Succeed", Result: result })
  })
})
app.get('/', verifyUser, (req, res) => {
  return res.json({ Status: "Succeed" })
})
app.post('/apply', (req, res) => {
  const profile = [
    req.body.id,
    req.body.name,
    req.body.email,
    req.body.nationality,
    req.body.sex,
    req.body.age,
    req.body.phone,
    req.body.passport_no,
    req.body.address,
  ]
  const sql = 'INSERT INTO greylist (id, name, email, nationality, sex, age, phone_no, passport_no, address) VALUES (?)';
  db.query(sql, [profile], (err, result) => {
    if (err) throw err;
    res.send('Added to greylist');
  });
});
app.post('/updateRecord', (req, res) => {
  console.log(req.body)
  const { id, record, standings } = req.body;
  const sql = "UPDATE event_archive SET record = ?, standings = ? WHERE id = ?";
  db.query(sql, [record, standings, id], (err, result) => {
    if (err) {
      console.error('SQL error:', err);
      return res.json({ Status: "Failed", Error: err });
    }
    return res.json({ Status: "Succeed" });
  });
});
app.post("/register", (req, res) => {
  const checkEmailSql = "SELECT * FROM comp_info WHERE email = ?";
  db.query(checkEmailSql, [req.body.email], (err, result) => {
    if (err) return res.json({ Error: "Failed" });
    if (result.length > 0) {
      return res.json({ Error: "EmailExists" });
    }
    else {
      const sql = "INSERT INTO comp_info (id, name, sex, age, email, phone, address, passport_no, nationality, password) VALUES (default,?)"
      console.log(req.body)
      bcrypt.hash(req.body.password.toString(), 5, (err, hash) => {
        if (err) return res.json({ Error: "HashFailed" })
        const values = [
          req.body.name,
          req.body.gender,
          req.body.age,
          req.body.email,
          req.body.number,
          req.body.address,
          req.body.passport,
          req.body.nationality,
          hash
        ]
        db.query(sql, [values], (err, result) => {
          if (err) return res.json({ Error: "Failed" })
          return res.json({ Status: "Succeed" })
        })
      })
    }
  })
})
app.post("/login", (req, res) => {
  if (req.body.type === "competitor") {
    const sql = "SELECT * FROM comp_info WHERE email = ?";
    db.query(sql, [req.body.email], (err, result) => {
      if (err) return res.json({ Error: "Failed" })
      if (result.length > 0) {
        bcrypt.compare(req.body.password, result[0].password, (err, response) => {
          if (response) {
            const token = jwt.sign({ email: result[0].email }, "jwtSecret", {
              expiresIn: "1h"
            })
            res.cookie("token", token, {
              httpOnly: true
            })
            return res.json({ Status: "Succeed" })
          }
          else {
            return res.json({ Error: "Failed-password" })
          }
        })
      }
      else {
        return res.json({ Error: "Failed-no-email" })
      }
    })
  } else if (req.body.type === "organizer") {
    const sql = "SELECT * FROM organization_info WHERE email = ? AND password = ?";
    db.query(sql, [req.body.email, req.body.password], (err, result) => {
      if (err) return res.json({ Error: "Failed" })
      if (result.length > 0) {
        return res.json({ Status: "Succeed" })
      }
      else {
        return res.json({ Error: "Failed" })
      }
    })
  } else {
    return res.json({ Error: "Invalid type" })
  }
})
app.get("/getEvents", (req, res) => {
  const sql = "SELECT * FROM event_info";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Error: "Failed" })
    return res.json({ Status: "Succeed", List: result })
  })
})
app.post("/approve", (req, res) => {
  console.log(req.body)
  const { id, name, email, nationality, sex, age, phone_no, passport_no, address } = req.body;
  const sql = "INSERT INTO event_info (entry_id, id, name, email, nationality, sex, age, phone_no, passport_no, address) VALUES (default, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
  db.query(sql, [id, name, email, nationality, sex, age, phone_no, passport_no, address], (err, result) => {
    if (err) {
      return res.json({ Status: "Failed", Error: err })
    }
    return res.json({ Status: "Succeed" })
  })
})
app.delete('/deleteGreylist/:id', (req, res) => {
  const { id } = req.params;
  const sql = "DELETE FROM greylist WHERE id = ?";
  db.query(sql, [id], (err, result) => {
    if (err) {
      return res.json({ Error: "Failed to delete approved entry" });
    }
    return res.json({ Status: "Succeed" });
  });
})
app.get("/getGreylist", (req, res) => {
  const sql = "SELECT * FROM greylist";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Error: "Failed" })
    return res.json({ Status: "Succeed", List: result })
  })
})
app.delete('/deleteEvent/:id', (req, res) => {
  const { id } = req.params;
  const sql = "DELETE FROM event_info WHERE entry_id = ?";
  db.query(sql, [id], (err, result) => {
    if (err) {
      return res.json({ Error: "Failed to delete event" });
    }
    return res.json({ Status: "Succeed" });
  });
});
app.get('/logout', (req, res) => {
  res.clearCookie('token')
  return res.json({ Status: "Succeed" })
})
app.listen(8081, () => {
  console.log('server started');
})
