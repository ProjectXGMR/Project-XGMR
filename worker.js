export default {
  async fetch(request, env) {
    return Response.json({
      worker: true,
      database: !!env.DB
    });
  }
};
