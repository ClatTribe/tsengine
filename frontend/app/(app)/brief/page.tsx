import { redirect } from "next/navigation";

// /brief moved to /engineer.
//
// The URL named the ARTIFACT (a brief) when the page is the AI Security Engineer's console — one of the
// two products the platform sells. Kept as a redirect rather than deleted: the two depth specialists,
// the Issues action strip and the command palette all pointed here, and a bookmark should not 404
// because the information architecture improved.
export default function BriefRedirect() {
  redirect("/engineer");
}
