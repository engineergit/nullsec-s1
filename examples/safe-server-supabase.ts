// Safe example: service_role is used only inside server-only code.
// Expected result: findings: [].

import "server-only";
import { createClient } from "@supabase/supabase-js";

export const supabaseAdmin = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
);

export async function loadAuditSummary() {
  const { data, error } = await supabaseAdmin
    .from("audit_summary")
    .select("day,count");
  if (error) throw error;
  return data;
}
