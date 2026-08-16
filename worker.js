export default {
  async fetch(request, env) {
    const result = await env.DB
      .prepare("SELECT * FROM users")
      .all();

    return Response.json({
      success: true,
      users: result.results
    });
  }
};
