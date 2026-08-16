const axios=require("axios");
module.exports=async(req,res)=>{ const r=await axios.get(req.query.url); res.send(r.data); };
