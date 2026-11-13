import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ChevronLeft,
  ChevronRight,
  FileKey2,
  RefreshCw,
  Search,
} from 'lucide-react';

type Certificate = {
  serial_number: string;
  subject_dn: string;
  issuer_dn: string;
  username?: string | null;
  status: string;
  validity_status?: string;
  certificate_profile?: string | null;
  not_before: string | null;
  expires_at: string | null;
  fingerprint: string | null;
  model: string;
  source: 'EJBCA' | 'COMPOSITE';
};

type ApiResponse = {
  items: any[];
  pagination: {
    page: number;
    page_size: number;
    total: number;
    total_pages: number;
  };
};

const PAGE_SIZE = 20;
const API_PAGE_SIZE = 100;

function getCommonName(dn: string): string {
  const match = dn.match(/(?:^|,)\s*CN=([^,]+)/i);
  return match ? match[1].trim() : dn;
}

function getModel(certificate: Certificate): string {
  if (certificate.source === 'COMPOSITE') {
    return 'Composite';
  }

  const issuer = certificate.issuer_dn.toLowerCase();

  if (issuer.includes('hybrid')) return 'Chimera';
  if (issuer.includes('classic')) return 'Classic';

  return 'Unknown';
}

function getStatus(certificate: Certificate): string {
  const status = certificate.status.toUpperCase();
  const validity = certificate.validity_status?.toUpperCase();

  if (status === 'REVOKED') return 'Revoked';

  if (status === 'EXPIRED' || validity === 'EXPIRED') {
    return 'Expired';
  }

  if (validity === 'NOT_YET_VALID') {
    return 'Not yet valid';
  }

  if (certificate.expires_at) {
    const expiration = new Date(certificate.expires_at).getTime();
    const now = Date.now();

    if (
      !Number.isNaN(expiration) &&
      expiration > now &&
      expiration <= now + 30 * 24 * 60 * 60 * 1000
    ) {
      return 'Expiring';
    }
  }

  if (status === 'ACTIVE' || validity === 'VALID') {
    return 'Active';
  }

  return status;
}

function formatDate(value: string | null): string {
  if (!value) return '—';

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) return '—';

  return date.toLocaleDateString('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
  });
}

function normalizeEJBCA(item: any): Certificate {
  return {
    serial_number: item.serial_number,
    subject_dn: item.subject_dn,
    issuer_dn: item.issuer_dn,
    username: item.username ?? null,
    status: item.status ?? 'UNKNOWN',
    validity_status: item.validity_status,
    certificate_profile: item.certificate_profile ?? null,
    not_before: item.not_before ?? null,
    expires_at: item.expires_at ?? null,
    fingerprint: item.fingerprint ?? null,
    model: getModel({
      ...item,
      source: 'EJBCA',
    }),
    source: 'EJBCA',
  };
}

function normalizeComposite(item: any): Certificate {
  return {
    serial_number: item.serial_number,
    subject_dn: item.subject_dn,
    issuer_dn: item.issuer_dn,
    username: null,
    status: item.status ?? 'UNKNOWN',
    not_before: item.not_before ?? null,
    expires_at: item.expires_at ?? null,
    fingerprint: item.fingerprint ?? null,
    model: 'Composite',
    source: 'COMPOSITE',
  };
}

async function fetchJSON(url: string): Promise<ApiResponse> {
  const response = await fetch(url, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw new Error(`${url}: HTTP ${response.status}`);
  }

  return response.json();
}

async function fetchInventory(
  endpoint: string,
): Promise<any[]> {
  const firstPage = await fetchJSON(
    `${endpoint}?page=1&page_size=${API_PAGE_SIZE}`,
  );

  const items = [...(firstPage.items ?? [])];
  const totalPages = firstPage.pagination?.total_pages ?? 1;

  if (totalPages > 1) {
    const remainingPages = await Promise.all(
      Array.from({ length: totalPages - 1 }, (_, index) =>
        fetchJSON(
          `${endpoint}?page=${index + 2}&page_size=${API_PAGE_SIZE}`,
        ),
      ),
    );

    for (const page of remainingPages) {
      items.push(...(page.items ?? []));
    }
  }

  return items;
}

export default function Certificates() {
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [page, setPage] = useState(1);

  const [query, setQuery] = useState('');
  const [modelFilter, setModelFilter] = useState('All models');
  const [statusFilter, setStatusFilter] = useState('All statuses');

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const loadCertificates = useCallback(async () => {
    setLoading(true);
    setError('');

    try {
      const [ejbcaItems, compositeItems] = await Promise.all([
        fetchInventory('/api/ejbca/certificates'),
        fetchInventory('/api/composite/certificates'),
      ]);

      const normalizedEJBCA = ejbcaItems.map(normalizeEJBCA);
      const normalizedComposite = compositeItems.map(normalizeComposite);

      const combined = [
        ...normalizedEJBCA,
        ...normalizedComposite,
      ];

      combined.sort((a, b) => {
        const dateA = a.not_before
          ? new Date(a.not_before).getTime()
          : 0;

        const dateB = b.not_before
          ? new Date(b.not_before).getTime()
          : 0;

        return dateB - dateA;
      });

      setCertificates(combined);
      setPage(1);
      setLastUpdated(new Date());
    } catch (err) {
      console.error('Unable to retrieve PKI certificates:', err);

      setError(
        err instanceof Error
          ? err.message
          : 'Unable to retrieve certificates from the PKI',
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadCertificates();
  }, [loadCertificates]);

  const filtered = useMemo(() => {
    return certificates.filter((certificate) => {
      const commonName = getCommonName(certificate.subject_dn);
      const model = getModel(certificate);
      const status = getStatus(certificate);

      const searchText = [
        commonName,
        certificate.subject_dn,
        certificate.issuer_dn,
        certificate.serial_number,
        certificate.username ?? '',
        certificate.source,
      ]
        .join(' ')
        .toLowerCase();

      const matchesSearch = searchText.includes(query.toLowerCase());

      const matchesModel =
        modelFilter === 'All models' || model === modelFilter;

      const matchesStatus =
        statusFilter === 'All statuses' || status === statusFilter;

      return matchesSearch && matchesModel && matchesStatus;
    });
  }, [certificates, query, modelFilter, statusFilter]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));

  const visibleCertificates = filtered.slice(
    (page - 1) * PAGE_SIZE,
    page * PAGE_SIZE,
  );

  const activeCount = certificates.filter(
    (certificate) => getStatus(certificate) === 'Active',
  ).length;

  const revokedCount = certificates.filter(
    (certificate) => getStatus(certificate) === 'Revoked',
  ).length;

  const expiringCount = certificates.filter(
    (certificate) => getStatus(certificate) === 'Expiring',
  ).length;

  return (
    <section className="panel full">
      <div className="paneltitle">
        <div>
          <h2>Certificate inventory</h2>
          <p>
            Unified inventory from EJBCA and the Composite PKI.
          </p>
        </div>

        <button
          className="btn secondary"
          onClick={loadCertificates}
          disabled={loading}
        >
          <RefreshCw
            size={16}
            className={loading ? 'spinning' : ''}
          />
          Refresh
        </button>
      </div>

      {!loading && !error && (
        <>
          <div className="ca-summary">
            <div>
              <span>Total certificates</span>
              <strong>{certificates.length}</strong>
            </div>

            <div>
              <span>Active</span>
              <strong>{activeCount}</strong>
            </div>

            <div>
              <span>Expiring soon</span>
              <strong>{expiringCount}</strong>
            </div>

            <div>
              <span>Revoked</span>
              <strong>{revokedCount}</strong>
            </div>
          </div>

          <div className="ca-live-label">
            <span />
            LIVE DATA · EJBCA + COMPOSITE
          </div>
        </>
      )}

      <div className="toolbar">
        <div className="search">
          <Search />
          <input
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setPage(1);
            }}
            placeholder="Search by CN, serial number, username or issuer..."
          />
        </div>

        <select
          value={modelFilter}
          onChange={(event) => {
            setModelFilter(event.target.value);
            setPage(1);
          }}
        >
          <option>All models</option>
          <option>Classic</option>
          <option>Chimera</option>
          <option>Composite</option>
          <option>Unknown</option>
        </select>

        <select
          value={statusFilter}
          onChange={(event) => {
            setStatusFilter(event.target.value);
            setPage(1);
          }}
        >
          <option>All statuses</option>
          <option>Active</option>
          <option>Expiring</option>
          <option>Expired</option>
          <option>Revoked</option>
          <option>Not yet valid</option>
        </select>

        <button
          className="btn secondary"
          onClick={() => {
            setQuery('');
            setModelFilter('All models');
            setStatusFilter('All statuses');
            setPage(1);
          }}
        >
          Reset
        </button>
      </div>

      <div className="tablewrap">
        <table>
          <thead>
            <tr>
              <th>COMMON NAME</th>
              <th>MODEL</th>
              <th>ISSUER</th>
              <th>SERIAL NUMBER</th>
              <th>EXPIRES</th>
              <th>STATUS</th>
            </tr>
          </thead>

          <tbody>
            {visibleCertificates.map((certificate) => {
              const model = getModel(certificate);
              const status = getStatus(certificate);

              return (
                <tr
                  key={`${certificate.source}-${certificate.serial_number}`}
                >
                  <td>
                    <FileKey2 className="keyicon" />
                    {getCommonName(certificate.subject_dn)}
                  </td>

                  <td>
                    <span className={`model ${model.toLowerCase()}`}>
                      {model}
                    </span>
                  </td>

                  <td>{getCommonName(certificate.issuer_dn)}</td>

                  <td>
                    <code>{certificate.serial_number}</code>
                  </td>

                  <td>{formatDate(certificate.expires_at)}</td>

                  <td>
                    <span
                      className={
                        'status ' +
                        status.toLowerCase().replace(/\s+/g, '-')
                      }
                    >
                      <i />
                      {status}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {loading && (
          <p className="empty">
            Retrieving certificates from EJBCA and Composite PKI...
          </p>
        )}

        {!loading && !error && filtered.length === 0 && (
          <p className="empty">
            No certificates match your search or filters.
          </p>
        )}

        {!loading && error && (
          <div className="empty">
            <strong>Unable to load certificates</strong>
            <p>{error}</p>
            <button
              className="btn secondary"
              onClick={loadCertificates}
            >
              Retry
            </button>
          </div>
        )}
      </div>

      {!loading && !error && (
        <div className="tablefoot">
          <span>
            Showing <b>{visibleCertificates.length}</b> of{' '}
            <b>{filtered.length}</b> filtered certificates.
            {' '}Total loaded: <b>{certificates.length}</b>
          </span>

          <div className="pagination">
            <button
              className="btn secondary"
              disabled={page <= 1}
              onClick={() => setPage((current) => current - 1)}
            >
              <ChevronLeft size={16} />
              Previous
            </button>

            <span>
              Page <b>{page}</b> of <b>{totalPages}</b>
            </span>

            <button
              className="btn secondary"
              disabled={page >= totalPages}
              onClick={() => setPage((current) => current + 1)}
            >
              Next
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      )}

      {!loading && !error && lastUpdated && (
        <div className="ca-last-updated">
          Last updated: {lastUpdated.toLocaleTimeString('en-GB')}
          <p>
            EJBCA inventory currently includes active certificates only.
            Composite inventory includes all indexed certificate states.
          </p>
        </div>
      )}
    </section>
  );
}
