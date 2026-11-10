// Servidor HTTP generico para Deno: sirve el handler de main.ts.
import handler from "./main.ts";
const port = Number(Deno.env.get("PORT") ?? "8000");
Deno.serve({ port, hostname: "0.0.0.0" }, (req: Request) => handler(req));
