cd ~/BugHunting-with-ai- && git fetch --all && git reset --hard origin/main && python3 -c "
from core.ai_engine_fast import ask_ai, is_ai_available, get_active_provider, ask_many
from core.ai_cache_layer import get_cache, cached_call
from core.ai_parallel import parallel_ai_calls, batch_triage
print('✅ All fast engine modules loaded')
print('AI available:', is_ai_available())
c = get_cache()
print('Cache stats:', c.stats())
"