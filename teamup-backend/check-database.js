const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, 'teamup.db');
const db = new sqlite3.Database(dbPath);

console.log('=== USERS TABLE ===');
db.all("SELECT * FROM users", (err, rows) => {
    if (err) {
        console.error('Error reading users:', err);
    } else {
        console.log(rows);
    }
    
    console.log('\n=== PROFILES TABLE ===');
    db.all("SELECT * FROM profiles", (err, profileRows) => {
        if (err) {
            console.error('Error reading profiles:', err);
        } else {
            console.log(profileRows);
        }
        
        db.close();
    });
});