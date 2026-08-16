package cmdisample
import ("net/http";"os/exec")
func H(w http.ResponseWriter, r *http.Request){ exec.Command("sh","-c","ping "+r.URL.Query().Get("h")).Run() }
