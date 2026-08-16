const fs=require("fs");
module.exports=(req,res)=>{ res.send(fs.readFileSync("/var/data/"+req.query.f)); };
