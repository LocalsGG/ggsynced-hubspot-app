import { createClient } from '@supabase/supabase-js';

let supabaseClient = null;

function getSupabaseClient() {
  if (!supabaseClient) {
    const supabaseUrl = process.env.SUPABASE_URL;
    const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
    const schema = process.env.SUPABASE_SCHEMA || 'ggsynced';

    if (!supabaseUrl || !supabaseKey) {
      throw new Error('Missing Supabase credentials');
    }

    supabaseClient = createClient(supabaseUrl, supabaseKey, {
      db: { schema }
    });
  }
  return supabaseClient;
}

// HubSpot token operations
export async function storeHubSpotTokens(userId, tokens) {
  const expiresAt = new Date(Date.now() + tokens.expires_in * 1000);
  
  const { error } = await getSupabaseClient()
    .from('hubspot_accounts')
    .upsert({
      user_id: userId,
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      expires_at: expiresAt.toISOString(),
      updated_at: new Date().toISOString()
    }, {
      onConflict: 'user_id'
    });

  if (error) throw error;
}

export async function getHubSpotToken(userId) {
  const { data, error } = await getSupabaseClient()
    .from('hubspot_accounts')
    .select('*')
    .eq('user_id', userId)
    .single();

  if (error && error.code !== 'PGRST116') throw error;
  return data;
}

// Start.gg token operations
export async function storeStartGGTokens(userId, tokens) {
  const expiresAt = new Date(Date.now() + tokens.expires_in * 1000);
  
  const { error } = await getSupabaseClient()
    .from('startgg_accounts')
    .upsert({
      user_id: userId,
      startgg_user_id: tokens.user_id || null,
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      expires_at: expiresAt.toISOString(),
      updated_at: new Date().toISOString()
    }, {
      onConflict: 'user_id'
    });

  if (error) throw error;
}

export async function getStartGGToken(userId) {
  const { data, error } = await getSupabaseClient()
    .from('startgg_accounts')
    .select('*')
    .eq('user_id', userId)
    .single();

  if (error && error.code !== 'PGRST116') throw error;
  return data;
}
