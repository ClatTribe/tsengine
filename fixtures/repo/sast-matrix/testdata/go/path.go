package pathsample
import ("net/http";"os")
func H(w http.ResponseWriter, r *http.Request) { os.ReadFile("/var/data/" + r.URL.Query().Get("f")) }
