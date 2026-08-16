const cp=require("child_process");
module.exports=(req,res)=>{ cp.exec("ping -c 1 "+req.query.host, (e,o)=>res.send(o)); };
