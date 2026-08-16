process.env.NODE_TLS_REJECT_UNAUTHORIZED="0";
const https=require("https");
module.exports=(u,cb)=>https.get(u,{rejectUnauthorized:false},cb);
