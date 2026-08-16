module.exports=(db,req,res)=>{ db.collection("u").find({$where:"this.n=='"+req.query.n+"'"}).toArray().then(r=>res.json(r)); };
