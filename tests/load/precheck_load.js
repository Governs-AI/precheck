import http from 'k6/http';
import exec from 'k6/execution';
import { check } from 'k6';

const baseUrl = (__ENV.PRECHECK_BASE_URL || 'http://127.0.0.1:8082').replace(
  /\/$/,
  '',
);
const apiKey = __ENV.PRECHECK_API_KEY;
const userPoolSize = Number(__ENV.LOAD_USER_POOL_SIZE || 120);
const rate = Number(__ENV.LOAD_RATE || 100);
const duration = __ENV.LOAD_DURATION || '30s';
const preAllocatedVUs = Number(__ENV.LOAD_PREALLOCATED_VUS || 50);
const maxVUs = Number(__ENV.LOAD_MAX_VUS || 200);

if (!apiKey) {
  throw new Error('PRECHECK_API_KEY is required');
}

if (!Number.isFinite(userPoolSize) || userPoolSize < 2) {
  throw new Error('LOAD_USER_POOL_SIZE must be at least 2');
}

export const options = {
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)', 'p(99)'],
  thresholds: {
    http_req_duration: ['p(95)<200'],
    http_req_failed: ['rate<0.01'],
    checks: ['rate>0.99'],
  },
  scenarios: {
    precheck_constant_rate: {
      executor: 'constant-arrival-rate',
      rate,
      timeUnit: '1s',
      duration,
      preAllocatedVUs,
      maxVUs,
      gracefulStop: '0s',
    },
  },
};

function buildPayload(iteration) {
  return JSON.stringify({
    tool: 'model.chat',
    scope: 'net.internal',
    raw_text: 'Load-test clean text that should not trigger PII redaction.',
    user_id: `load-user-${iteration % userPoolSize}`,
    corr_id: `load-${iteration}`,
    tags: ['load', 'ci'],
  });
}

export default function () {
  const iteration = exec.scenario.iterationInTest;
  const response = http.post(`${baseUrl}/api/v1/precheck`, buildPayload(iteration), {
    headers: {
      'Content-Type': 'application/json',
      'X-Governs-Key': apiKey,
    },
    tags: {
      endpoint: 'precheck',
    },
  });

  let body = null;
  if (response.status === 200) {
    try {
      body = response.json();
    } catch (_) {
      body = null;
    }
  }

  check(response, {
    'status is 200': (res) => res.status === 200,
    'response contains decision': () => Boolean(body && body.decision),
  });
}
