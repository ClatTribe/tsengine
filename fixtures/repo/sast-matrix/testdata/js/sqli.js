module.exports=(db,req,res)=>{ db.query("SELECT * FROM users WHERE n='"+req.query.n+"'",(e,r)=>res.json(r)); };
