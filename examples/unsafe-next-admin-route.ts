// Unsafe example: Next.js admin mutation without session/role check.
// Expected category: UNSAFE_ADMIN_ROUTE (and often BROKEN_AUTH if ownership is involved).

export async function POST(req: Request) {
  const { userId, role } = await req.json();
  await db.user.update({ where: { id: userId }, data: { role } });
  return Response.json({ ok: true });
}
