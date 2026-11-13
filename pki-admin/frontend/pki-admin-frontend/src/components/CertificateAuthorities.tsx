import { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  CalendarDays,
  CheckCircle2,
  CircleHelp,
  RefreshCw,
  Shield,
  ShieldCheck,
} from 'lucide-react';

type CertificateAuthority = {
  id: number;
  name: string;
  subject_dn: string;
  issuer_dn: string;
  expiration_date: string;
  external: boolean;
};

type AuthoritiesResponse = {
  count: number;
  certificate_authorities: CertificateAuthority[];
};

type Model = 'Classic' | 'Chimera' | 'Management' | 'Unknown';

function getModel(name: string): Model {
  const normalized = name.toLowerCase();

  if (normalized.includes('classic')) return 'Classic';
  if (normalized.includes('hybrid')) return 'Chimera';
  if (normalized.includes('management')) return 'Management';

  return 'Unknown';
}

function getType(ca: CertificateAuthority): string {
  return ca.subject_dn === ca.issuer_dn
    ? 'ROOT AUTHORITY'
    : 'INTERMEDIATE AUTHORITY';
}

function formatDate(value: string): string {
  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    timeZone: 'UTC',
  }).format(date);
}

function getDaysRemaining(value: string): number | null {
  const expiration = new Date(value);

  if (Number.isNaN(expiration.getTime())) {
    return null;
  }

  return Math.ceil(
    (expiration.getTime() - Date.now()) / (1000 * 60 * 60 * 24),
  );
}

export default function CertificateAuthorities() {
  const [authorities, setAuthorities] = useState<CertificateAuthority[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const loadAuthorities = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/ejbca/cas');

      if (!response.ok) {
        throw new Error(`Backend returned HTTP ${response.status}`);
      }

      const data: AuthoritiesResponse = await response.json();

      if (!Array.isArray(data.certificate_authorities)) {
        throw new Error('Invalid response received from backend');
      }

      setAuthorities(data.certificate_authorities);
      setLastUpdated(new Date());
    } catch (err) {
      console.error('Unable to retrieve certificate authorities:', err);

      setError(
        err instanceof Error
          ? err.message
          : 'Unable to retrieve certificate authorities',
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAuthorities();
  }, [loadAuthorities]);

  return (
    <section className="panel full">
      <div className="paneltitle ca-heading">
        <div>
          <h2>CA hierarchy</h2>
          <p>
            Root and intermediate certification authorities registered in
            EJBCA.
          </p>
        </div>

        <button
          className="ca-refresh"
          onClick={loadAuthorities}
          disabled={loading}
        >
          <RefreshCw className={loading ? 'spinning' : ''} />
          Refresh
        </button>
      </div>

      <div className="ca-summary">
        <div>
          <span>Total authorities</span>
          <strong>{loading ? '—' : authorities.length}</strong>
        </div>

        <div>
          <span>Root authorities</span>
          <strong>
            {loading
              ? '—'
              : authorities.filter((ca) => getType(ca) === 'ROOT AUTHORITY')
                  .length}
          </strong>
        </div>

        <div>
          <span>Intermediate authorities</span>
          <strong>
            {loading
              ? '—'
              : authorities.filter(
                  (ca) => getType(ca) === 'INTERMEDIATE AUTHORITY',
                ).length}
          </strong>
        </div>
      </div>

      {loading && (
        <div className="ca-message">
          <RefreshCw className="spinning" />
          <span>Retrieving certificate authorities from EJBCA...</span>
        </div>
      )}

      {!loading && error && (
        <div className="ca-error">
          <AlertTriangle />
          <div>
            <strong>Unable to load certificate authorities</strong>
            <p>{error}</p>
            <button className="btn secondary" onClick={loadAuthorities}>
              <RefreshCw />
              Retry connection
            </button>
          </div>
        </div>
      )}

      {!loading && !error && authorities.length === 0 && (
        <div className="ca-message">
          <CircleHelp />
          <span>No certificate authorities were returned by EJBCA.</span>
        </div>
      )}

      {!loading && !error && authorities.length > 0 && (
        <>
          <div className="ca-live-label">
            <span />
            LIVE DATA FROM EJBCA
          </div>

          <div className="ca-grid">
            {authorities.map((ca) => {
              const model = getModel(ca.name);
              const type = getType(ca);
              const days = getDaysRemaining(ca.expiration_date);

              return (
                <article className="ca-authority" key={ca.id}>
                  <div className="ca-card-top">
                    <div className="ca-icon">
                      {type === 'ROOT AUTHORITY' ? (
                        <ShieldCheck />
                      ) : (
                        <Shield />
                      )}
                    </div>

                    <span className="ca-readonly">
                      <CheckCircle2 />
                      Registered
                    </span>
                  </div>

                  <small className="ca-type">
                    {type} · {model.toUpperCase()}
                  </small>

                  <h3>{ca.name}</h3>

                  <div className="ca-details">
                    <div>
                      <span>CA ID</span>
                      <b>{ca.id}</b>
                    </div>

                    <div>
                      <span>Subject DN</span>
                      <b title={ca.subject_dn}>{ca.subject_dn}</b>
                    </div>

                    <div>
                      <span>Issuer DN</span>
                      <b title={ca.issuer_dn}>{ca.issuer_dn}</b>
                    </div>

                    <div>
                      <span>Expiration date</span>
                      <b>
                        <CalendarDays />
                        {formatDate(ca.expiration_date)}
                      </b>
                    </div>

                    {days !== null && (
                      <div>
                        <span>Validity remaining</span>
                        <b className={days < 0 ? 'expired' : ''}>
                          {days < 0
                            ? `Expired ${Math.abs(days)} days ago`
                            : `${days} days`}
                        </b>
                      </div>
                    )}
                  </div>

                  <div className="ca-card-footer">
                    <span>EJBCA registration</span>
                    <span className="ca-external">
                      {ca.external ? 'External CA' : 'Internal CA'}
                    </span>
                  </div>
                </article>
              );
            })}
          </div>

          <div className="ca-last-updated">
            Last updated:{' '}
            {lastUpdated?.toLocaleTimeString('en-GB') ?? 'Unknown'}
          </div>
        </>
      )}
    </section>
  );
}
