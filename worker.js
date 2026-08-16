export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Strona główna
    if (url.pathname === "/") {
      return new Response(
        `<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>myproject</title>
</head>
<body>
  <h1>Utwórz konto</h1>

  <form id="registerForm">
    <input type="text" id="username" placeholder="Nazwa użytkownika" required>
    <input type="email" id="email" placeholder="E-mail" required>
    <input type="password" id="password" placeholder="Hasło" required>
    <button type="submit">Zarejestruj się</button>
  </form>

  <p id="message"></p>

  <script>
    const form = document.getElementById("registerForm");
    const message = document.getElementById("message");

    form.addEventListener("submit", async (event) => {
      event.preventDefault();

      const response = await fetch("/api/register", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          username: document.getElementById("username").value,
          email: document.getElementById("email").value,
          password: document.getElementById("password").value
        })
      });

      const data = await response.json();

      message.textContent = data.success
        ? "Konto zostało utworzone!"
        : data.error;
    });
  </script>
</body>
</html>`,
        {
          headers: {
            "Content-Type": "text/html; charset=UTF-8"
          }
        }
      );
    }

    // Rejestracja
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
