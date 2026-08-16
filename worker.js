export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/") {
      return Response.json({
        success: true,
        message: "myproject działa"
      });
    }

    if (url.pathname === "/api/register" && request.method === "POST") {
      try {
        const data = await request.json();

        const username = String(data.username || "").trim();
        const email = String(data.email || "").trim().toLowerCase();
        const password = String(data.password || "");

        if (!username || !email || !password) {
          return Response.json(
            { success: false, error: "Wszystkie pola są wymagane." },
            { status: 400 }
          );
        }

        if (password.length < 8) {
          return Response.json(
            { success: false, error: "Hasło musi mieć co najmniej 8 znaków." },
            { status: 400 }
          );
        }

        const existingUser = await env.DB
          .prepare("SELECT id FROM users WHERE username = ? OR email = ?")
          .bind(username, email)
          .first();

        if (existingUser) {
          return Response.json(
            { success: false, error: "Użytkownik lub e-mail już istnieje." },
            { status: 409 }
          );
        }

        const passwordBytes = new TextEncoder().encode(password);
        const hashBuffer = await crypto.subtle.digest("SHA-256", passwordBytes);

        const passwordHash = Array.from(new Uint8Array(hashBuffer))
          .map(byte => byte.toString(16).padStart(2, "0"))
          .join("");

        const result = await env.DB
          .prepare(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)"
          )
          .bind(username, email, passwordHash)
          .run();

        const userId = result.meta.last_row_id;

        await env.DB
          .prepare("INSERT INTO profiles (user_id, display_name) VALUES (?, ?)")
          .bind(userId, username)
          .run();

        return Response.json({
          success: true,
          message: "Konto zostało utworzone.",
          user: {
            id: userId,
            username,
            email
          }
        });
      } catch (error) {
        return Response.json(
          {
            success: false,
            error: "Nie udało się utworzyć konta."
          },
          { status: 500 }
        );
      }
    }

    return Response.json(
      { success: false, error: "Nie znaleziono strony." },
      { status: 404 }
    );
  }
};
