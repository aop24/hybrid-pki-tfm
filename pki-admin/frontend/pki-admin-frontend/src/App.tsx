import { useMemo, useState } from 'react';

import {
  Activity,
  AlertTriangle,
  Bell,
  ChevronDown,
  ChevronRight,
  Clock3,
  Download,
  FileBadge,
  FileCheck2,
  FileClock,
  FileKey2,
  LayoutDashboard,
  LockKeyhole,
  Menu,
  MoreHorizontal,
  Network,
  Plus,
  Search,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  SlidersHorizontal,
  X,
} from 'lucide-react';

import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import CertificateAuthorities from './components/CertificateAuthorities';
import Certificates from './components/Certificates';

type Page =
  | 'Dashboard'
  | 'Certificates'
  | 'Certificate Authorities'
  | 'OCSP Services'
  | 'Nodes'
  | 'Audit Logs';

type CertStatus = 'Active' | 'Expiring' | 'Revoked';

type Certificate = {
  cn: string;
  model: string;
  issuer: string;
  algorithm: string;
  expires: string;
  status: CertStatus;
};

const initial: Certificate[] = [
  {
    cn: 'client-01-chimera',
    model: 'Chimera',
    issuer: 'TFM Sub CA Hybrid',
    algorithm: 'ECDSA P-256 + ML-DSA-65',
    expires: '12 Nov 2028',
    status: 'Active',
  },
  {
    cn: 'client-02-composite',
    model: 'Composite',
    issuer: 'TFM Sub CA Composite',
    algorithm: 'P-384 + ML-DSA-65',
    expires: '11 Nov 2028',
    status: 'Active',
  },
  {
    cn: 'client-03-classic',
    model: 'Classic',
    issuer: 'TFM Sub CA Classic',
    algorithm: 'ECDSA P-256',
    expires: '10 Nov 2028',
    status: 'Active',
  },
  {
    cn: 'gateway-01-chimera',
    model: 'Chimera',
    issuer: 'TFM Sub CA Hybrid',
    algorithm: 'ECDSA P-256 + ML-DSA-65',
    expires: '02 Dec 2026',
    status: 'Expiring',
  },
  {
    cn: 'client-04-classic',
    model: 'Classic',
    issuer: 'TFM Sub CA Classic',
    algorithm: 'ECDSA P-256',
    expires: '18 Oct 2028',
    status: 'Revoked',
  },
];

const trend = [
  { m: 'May', classic: 14, chimera: 8, composite: 5 },
  { m: 'Jun', classic: 19, chimera: 12, composite: 8 },
  { m: 'Jul', classic: 23, chimera: 17, composite: 12 },
  { m: 'Aug', classic: 28, chimera: 21, composite: 16 },
  { m: 'Sep', classic: 32, chimera: 26, composite: 21 },
  { m: 'Oct', classic: 39, chimera: 31, composite: 27 },
  { m: 'Nov', classic: 46, chimera: 38, composite: 34 },
];

const nav: { label: Page; icon: any }[] = [
  { label: 'Dashboard', icon: LayoutDashboard },
  { label: 'Certificates', icon: FileBadge },
  { label: 'Certificate Authorities', icon: ShieldCheck },
  { label: 'OCSP Services', icon: Activity },
  { label: 'Nodes', icon: Network },
  { label: 'Audit Logs', icon: FileClock },
];

function Status({ value }: { value: string }) {
  return (
    <span className={'status ' + value.toLowerCase().replace(' ', '-')}>
      <i />
      {value}
    </span>
  );
}

function Model({ value }: { value: string }) {
  return (
    <span className={'model ' + value.toLowerCase()}>
      {value}
    </span>
  );
}

export default function App() {
  const [page, setPage] = useState<Page>('Dashboard');
  const [certs, setCerts] = useState(initial);
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('All models');
  const [menu, setMenu] = useState(false);
  const [modal, setModal] = useState(false);
  const [toast, setToast] = useState('');

  const msg = (s: string) => {
    setToast(s);
    setTimeout(() => setToast(''), 3000);
  };

  const filtered = useMemo(
    () =>
      certs.filter(
        (c) =>
          (c.cn + ' ' + c.issuer)
            .toLowerCase()
            .includes(query.toLowerCase()) &&
          (filter === 'All models' || c.model === filter),
      ),
    [certs, query, filter],
  );

  return (
    <div className="shell">
      <aside className={'sidebar ' + (menu ? 'open' : '')}>
        <div className="brand">
          <div className="brandmark">
            <Shield />
          </div>

          <div>
            <b>
              PKI<span>ADMIN</span>
            </b>
            <small>HYBRID INFRASTRUCTURE</small>
          </div>

          <button
            className="mobileclose"
            onClick={() => setMenu(false)}
          >
            <X />
          </button>
        </div>

        <div className="workspace">
          <LockKeyhole />
          <div>
            <b>UPV · TFM PKI</b>
            <small>Demo environment</small>
          </div>
          <ChevronDown />
        </div>

        <label className="navlabel">WORKSPACE</label>

        {nav.map((n) => (
          <button
            key={n.label}
            className={'navitem ' + (page === n.label ? 'active' : '')}
            onClick={() => {
              setPage(n.label);
              setMenu(false);
            }}
          >
            <n.icon />
            <span>{n.label}</span>
            {n.label === 'Certificates' && <em>118</em>}
          </button>
        ))}

        <label className="navlabel management">MANAGEMENT</label>

        <button
          className="navitem"
          onClick={() =>
            msg('Configuración disponible en una próxima iteración.')
          }
        >
          <Settings />
          <span>Settings</span>
        </button>

        <div className="sidebottom">
          <div className="secure">
            <ShieldCheck />
            <b>Infrastructure secure</b>
            <p>Services are represented with demo status.</p>
            <div />
          </div>

          <div className="user">
            <span>AO</span>
            <div>
              <b>PKI Administrator</b>
              <small>Administrator</small>
            </div>
            <MoreHorizontal />
          </div>
        </div>
      </aside>

      <main>
        <header className="topbar">
          <div className="crumb">
            <button
              className="hamb"
              onClick={() => setMenu(true)}
            >
              <Menu />
            </button>

            Workspace
            <ChevronRight />
            <b>{page}</b>
          </div>

          <div className="topright">
            <span className="demo">● DEMO ENVIRONMENT</span>

            <button
              className="bell"
              onClick={() => msg('No tienes notificaciones pendientes.')}
            >
              <Bell />
            </button>

            <span className="avatar">AO</span>
          </div>
        </header>

        <div className="content">
          <div className="heading">
            <div>
              <small>INFRASTRUCTURE OVERVIEW　/　NOVEMBER 2026</small>
              <h1>{page}</h1>
              <p>{pageText(page)}</p>
            </div>

            <div className="actions">
              <button
                className="btn secondary"
                onClick={() => msg('Informe de demostración preparado.')}
              >
                <Download />
                Export report
              </button>

              <button
                className="btn primary"
                onClick={() => setModal(true)}
              >
                <Plus />
                New certificate
              </button>
            </div>
          </div>

          {/* DASHBOARD */}

          {page === 'Dashboard' && (
            <>
              <div className="stats">
                <Stat
                  icon={FileBadge}
                  label="Total certificates"
                  value="118"
                  change="↗ 12.8%"
                />

                <Stat
                  icon={FileCheck2}
                  label="Active certificates"
                  value="107"
                  change="↗ 8.4%"
                  green
                />

                <Stat
                  icon={Clock3}
                  label="Expiring soon"
                  value="07"
                  change="Next 30 days"
                  amber
                />

                <Stat
                  icon={ShieldAlert}
                  label="Revoked certificates"
                  value="04"
                  change="No change"
                  red
                />
              </div>

              <div className="gridtop">
                <section className="panel chart">
                  <PanelTitle
                    title="Certificate issuance"
                    sub="Certificates issued over the last 7 months"
                  />

                  <div className="legend">
                    <span>● Classic</span>
                    <span>● Chimera</span>
                    <span>● Composite</span>
                  </div>

                  <div className="chartbox">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={trend}>
                        <defs>
                          <linearGradient
                            id="a"
                            x1="0"
                            y1="0"
                            x2="0"
                            y2="1"
                          >
                            <stop
                              offset="0%"
                              stopColor="#8999b5"
                              stopOpacity={0.2}
                            />
                            <stop
                              offset="100%"
                              stopColor="#8999b5"
                              stopOpacity={0}
                            />
                          </linearGradient>

                          <linearGradient
                            id="b"
                            x1="0"
                            y1="0"
                            x2="0"
                            y2="1"
                          >
                            <stop
                              offset="0%"
                              stopColor="#8979ff"
                              stopOpacity={0.2}
                            />
                            <stop
                              offset="100%"
                              stopColor="#8979ff"
                              stopOpacity={0}
                            />
                          </linearGradient>
                        </defs>

                        <CartesianGrid
                          stroke="#243044"
                          strokeDasharray="3 5"
                          vertical={false}
                        />

                        <XAxis
                          dataKey="m"
                          axisLine={false}
                          tickLine={false}
                          tick={{ fill: '#8190a5', fontSize: 11 }}
                        />

                        <YAxis
                          axisLine={false}
                          tickLine={false}
                          tick={{ fill: '#8190a5', fontSize: 11 }}
                        />

                        <Tooltip
                          contentStyle={{
                            background: '#111b2a',
                            border: '1px solid #334056',
                            borderRadius: 8,
                          }}
                        />

                        <Area
                          dataKey="classic"
                          stroke="#8999b5"
                          fill="url(#a)"
                          strokeWidth={2}
                        />

                        <Area
                          dataKey="chimera"
                          stroke="#8979ff"
                          fill="url(#b)"
                          strokeWidth={2}
                        />

                        <Area
                          dataKey="composite"
                          stroke="#27c5a5"
                          fill="#27c5a5"
                          fillOpacity={0.06}
                          strokeWidth={2}
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </section>

                <section className="panel distribution">
                  <PanelTitle
                    title="By cryptographic model"
                    sub="Certificate distribution"
                  />

                  <div className="donut">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={[
                            { name: 'Classic', value: 46, color: '#8495b2' },
                            { name: 'Chimera', value: 38, color: '#8979ff' },
                            { name: 'Composite', value: 34, color: '#27c5a5' },
                          ]}
                          dataKey="value"
                          innerRadius={59}
                          outerRadius={81}
                          paddingAngle={4}
                        >
                          {[
                            '#8495b2',
                            '#8979ff',
                            '#27c5a5',
                          ].map((c) => (
                            <Cell fill={c} key={c} />
                          ))}
                        </Pie>

                        <Tooltip />
                      </PieChart>
                    </ResponsiveContainer>

                    <div>
                      <b>118</b>
                      <small>Total issued</small>
                    </div>
                  </div>

                  <div className="distlegend">
                    <span>
                      ● Classic <b>46 <i>39%</i></b>
                    </span>
                    <span>
                      ● Chimera <b>38 <i>32%</i></b>
                    </span>
                    <span>
                      ● Composite <b>34 <i>29%</i></b>
                    </span>
                  </div>
                </section>
              </div>

              <div className="gridbottom">
                <section className="panel">
                  <PanelTitle
                    title="Certificate authorities"
                    sub="Health status of your CA hierarchy"
                    link="View all"
                    onLink={() => setPage('Certificate Authorities')}
                  />

                  <div className="ca">
                    <CA
                      name="TFM Root CA Classic"
                      type="ROOT AUTHORITY · RSA-4096 / SHA-256"
                      model="Classic"
                    />

                    <CA
                      name="TFM Sub CA Hybrid"
                      type="INTERMEDIATE · RSA-4096 + ML-DSA"
                      model="Chimera"
                    />

                    <CA
                      name="TFM Sub CA Composite"
                      type="INTERMEDIATE · P-384 + ML-DSA-65"
                      model="Composite"
                    />
                  </div>
                </section>

                <section className="panel">
                  <PanelTitle
                    title="Recent activity"
                    sub="Latest infrastructure events"
                    link="View logs"
                    onLink={() => setPage('Audit Logs')}
                  />

                  <div className="events">
                    <Event
                      title="Certificate issued"
                      detail="client-01-chimera · Chimera"
                      time="2 min ago"
                    />

                    <Event
                      title="Certificate revoked"
                      detail="client-04-classic · Classic"
                      time="1 hour ago"
                      bad
                    />

                    <Event
                      title="OCSP status check"
                      detail="Responder · All good"
                      time="3 hours ago"
                    />

                    <Event
                      title="Certificate issued"
                      detail="client-02-composite · Composite"
                      time="Yesterday"
                    />
                  </div>
                </section>
              </div>

              <section className="panel recent">
                <PanelTitle
                  title="Recently issued certificates"
                  sub="Latest certificates across all cryptographic models"
                  link="All certificates"
                  onLink={() => setPage('Certificates')}
                />

                <CertTable data={certs.slice(0, 4)} />
              </section>
            </>
          )}

          {/* CERTIFICATES */}

          {page === 'Certificates' && <Certificates />}

          {/* CERTIFICATE AUTHORITIES - REAL EJBCA DATA */}

          {page === 'Certificate Authorities' && (
            <CertificateAuthorities />
          )}

          {/* OCSP SERVICES */}

          {page === 'OCSP Services' && (
            <section className="panel full">
              <PanelTitle
                title="OCSP responders"
                sub="Certificate status validation services"
              />

              <div className="cards3">
                {[
                  [
                    'OCSP Classic',
                    'EJBCA responder',
                    'TFM Sub CA Classic',
                    'Operational',
                  ],
                  [
                    'OCSP Chimera',
                    'EJBCA responder',
                    'TFM Sub CA Hybrid',
                    'Operational',
                  ],
                  [
                    'OCSP Composite',
                    'OpenSSL responder',
                    'TFM Sub CA Composite',
                    'Not connected',
                  ],
                ].map((r) => (
                  <div className="tile" key={r[0]}>
                    <Activity />
                    <Status value={r[3]} />
                    <h3>{r[0]}</h3>
                    <p>{r[1]}</p>
                    <small>Issuer</small>
                    <b>{r[2]}</b>
                  </div>
                ))}
              </div>

              <Info>
                Composite uses a separate OpenSSL-based OCSP responder. The
                operational state shown here is illustrative and must be
                verified during integration.
              </Info>
            </section>
          )}

          {/* NODES */}

          {page === 'Nodes' && (
            <section className="panel full">
              <PanelTitle
                title="Registered nodes"
                sub="Clients enrolled in the hybrid PKI environment"
              />

              <div className="cards3">
                {[
                  ['client-01', '10.10.0.11', 'Chimera', 'Connected'],
                  ['client-02', '10.10.0.12', 'Composite', 'Connected'],
                  ['client-03', '10.10.0.13', 'Classic', 'Connected'],
                  ['gateway-01', '10.10.0.20', 'Chimera', 'Offline'],
                ].map((n) => (
                  <div className="tile" key={n[0]}>
                    <Server />
                    <Status value={n[3]} />
                    <h3>{n[0]}</h3>
                    <p>{n[1]}</p>
                    <small>Certificate model</small>
                    <Model value={n[2]} />
                  </div>
                ))}
              </div>

              <Info>
                Node inventory is illustrative. The panel is not querying
                WireGuard peers or certdist.
              </Info>
            </section>
          )}

          {/* AUDIT LOGS */}

          {page === 'Audit Logs' && (
            <section className="panel full">
              <PanelTitle
                title="Audit trail"
                sub="Administrative and infrastructure events"
              />

              <table>
                <thead>
                  <tr>
                    <th>TIMESTAMP</th>
                    <th>EVENT</th>
                    <th>RESOURCE</th>
                    <th>ACTOR</th>
                    <th>RESULT</th>
                  </tr>
                </thead>

                <tbody>
                  {[
                    [
                      '12 Nov 2026 · 09:42:18',
                      'CERTIFICATE_ISSUED',
                      'client-01-chimera',
                      'Administrator',
                    ],
                    [
                      '12 Nov 2026 · 09:40:03',
                      'OCSP_STATUS_CHECK',
                      'TFM Sub CA Hybrid',
                      'System',
                    ],
                    [
                      '12 Nov 2026 · 08:55:41',
                      'CERTIFICATE_REVOKED',
                      'client-04-classic',
                      'Administrator',
                    ],
                    [
                      '11 Nov 2026 · 17:21:09',
                      'CERTIFICATE_ISSUED',
                      'client-02-composite',
                      'Administrator',
                    ],
                    [
                      '11 Nov 2026 · 15:04:32',
                      'CA_HEALTH_CHECK',
                      'TFM Sub CA Classic',
                      'System',
                    ],
                  ].map((r) => (
                    <tr key={r[1] + r[0]}>
                      {r.map((v, i) => (
                        <td key={i}>
                          {i === 1 ? <code>{v}</code> : v}
                        </td>
                      ))}
                      <td>
                        <Status value="Success" />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          )}
        </div>

        <footer>
          <span>
            PKI ADMIN　<b>v0.1.0</b>
          </span>

          <span>● Demo data · Not connected to PKI services</span>

          <span>UPV · Cybersecurity & Cyberintelligence</span>
        </footer>
      </main>

      {menu && (
        <div
          className="backdrop"
          onClick={() => setMenu(false)}
        />
      )}

      {toast && (
        <div className="toast">
          <ShieldCheck />
          {toast}
          <button onClick={() => setToast('')}>
            <X />
          </button>
        </div>
      )}

      {modal && (
        <div
          className="modalback"
          onClick={() => setModal(false)}
        >
          <div
            className="modal"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              className="modalx"
              onClick={() => setModal(false)}
            >
              <X />
            </button>

            <small>CERTIFICATE MANAGEMENT</small>
            <h2>Request new certificate</h2>

            <p>
              Frontend preview only. Issuance is not connected to the PKI yet.
            </p>

            <label>
              Common name (CN)
              <input placeholder="e.g. client-05-classic" />
            </label>

            <label>
              Cryptographic model
              <select>
                <option>Classic · ECDSA P-256</option>
                <option>Chimera · ECDSA + ML-DSA</option>
                <option>Composite · P-384 + ML-DSA-65</option>
              </select>
            </label>

            <div className="modalactions">
              <button
                className="btn secondary"
                onClick={() => setModal(false)}
              >
                Cancel
              </button>

              <button
                className="btn primary"
                onClick={() => {
                  setModal(false);
                  msg('La emisión se habilitará al conectar el backend.');
                }}
              >
                Continue <ChevronRight />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function pageText(p: Page) {
  return {
    Dashboard: 'Monitor and manage your hybrid public key infrastructure.',
    Certificates: 'Search, inspect and manage certificates issued by your PKI.',
    'Certificate Authorities':
      'Explore the root and intermediate certification authorities.',
    'OCSP Services':
      'Monitor certificate status responders and availability.',
    Nodes: 'Review registered clients and their certificate assignments.',
    'Audit Logs': 'Track administrative activity across the PKI infrastructure.',
  }[p];
}

function PanelTitle({
  title,
  sub,
  link,
  onLink,
}: {
  title: string;
  sub: string;
  link?: string;
  onLink?: () => void;
}) {
  return (
    <div className="paneltitle">
      <div>
        <h2>{title}</h2>
        <p>{sub}</p>
      </div>

      {link && (
        <button onClick={onLink}>
          {link} <ChevronRight />
        </button>
      )}
    </div>
  );
}

function Stat({
  icon: Icon,
  label,
  value,
  change,
  green,
  amber,
  red,
}: {
  icon: any;
  label: string;
  value: string;
  change: string;
  green?: boolean;
  amber?: boolean;
  red?: boolean;
}) {
  return (
    <div className="stat">
      <div className="stathead">
        {label}
        <span className={green ? 'green' : amber ? 'amber' : red ? 'red' : ''}>
          <Icon />
        </span>
      </div>

      <strong>{value}</strong>

      <small className={green ? 'green' : amber ? 'amber' : red ? 'red' : 'green'}>
        {change}
      </small>

      <small className="muted">
        {amber ? 'Requires attention' : 'vs. previous month'}
      </small>
    </div>
  );
}

function CertTable({
  data,
  onRevoke,
}: {
  data: Certificate[];
  onRevoke?: (cn: string) => void;
}) {
  return (
    <div className="tablewrap">
      <table>
        <thead>
          <tr>
            <th>COMMON NAME</th>
            <th>MODEL</th>
            <th>ISSUER</th>
            <th>ALGORITHM</th>
            <th>EXPIRES</th>
            <th>STATUS</th>
            {onRevoke && <th />}
          </tr>
        </thead>

        <tbody>
          {data.map((c) => (
            <tr key={c.cn}>
              <td>
                <FileKey2 className="keyicon" />
                {c.cn}
              </td>
              <td>
                <Model value={c.model} />
              </td>
              <td>{c.issuer}</td>
              <td>{c.algorithm}</td>
              <td>{c.expires}</td>
              <td>
                <Status value={c.status} />
              </td>

              {onRevoke && (
                <td>
                  <button
                    className="more"
                    title="Revoke (demo)"
                    onClick={() => onRevoke(c.cn)}
                  >
                    <MoreHorizontal />
                  </button>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>

      {data.length === 0 && (
        <p className="empty">No certificates match your search.</p>
      )}
    </div>
  );
}

function CA({
  name,
  type,
  model,
}: {
  name: string;
  type: string;
  model: string;
}) {
  return (
    <div className="carow">
      <ShieldCheck />

      <div>
        <b>{name}</b>
        <small>{type}</small>
      </div>

      <Model value={model} />
      <Status value="Operational" />
    </div>
  );
}

function Event({
  title,
  detail,
  time,
  bad,
}: {
  title: string;
  detail: string;
  time: string;
  bad?: boolean;
}) {
  return (
    <div className="event">
      <span className={bad ? 'bad' : ''}>
        {bad ? <ShieldX /> : <FileCheck2 />}
      </span>

      <div>
        <b>{title}</b>
        <small>{detail}</small>
      </div>

      <time>{time}</time>
    </div>
  );
}

function Info({ children }: { children: string }) {
  return (
    <div className="info">
      <AlertTriangle />
      {children}
    </div>
  );
}
