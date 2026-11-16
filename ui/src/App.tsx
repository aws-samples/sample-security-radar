import { lazy, Suspense } from 'react';
import { HashRouter, Routes, Route, Navigate, useParams, useLocation } from 'react-router-dom';
import { ThemeProvider } from '@/contexts/ThemeContext';
import { Layout } from '@/components/Layout';
import { RadarPage } from '@/pages/RadarPage';
import { EventDetailPage } from '@/pages/EventDetailPage';

// R3.6: the home page and the event page are in the entry chunk — a pushed link opens an event page, mostly on a
// phone, and must not wait for a second request. Every other page is its own chunk, loaded when first visited.
// (The pages use named exports; lazy() needs a default.)
const page = <K extends string>(load: () => Promise<Record<K, React.ComponentType>>, name: K) =>
  lazy(() => load().then(m => ({ default: m[name] })));
const Web3Page = page(() => import('@/pages/Web3Page'), 'Web3Page');
const VulnPage = page(() => import('@/pages/VulnPage'), 'VulnPage');
const AnnouncementsPage = page(() => import('@/pages/AnnouncementsPage'), 'AnnouncementsPage');
const SearchPage = page(() => import('@/pages/SearchPage'), 'SearchPage');
const SubscribePage = page(() => import('@/pages/SubscribePage'), 'SubscribePage');
const SourcesPage = page(() => import('@/pages/SourcesPage'), 'SourcesPage');
const OpsPage = page(() => import('@/pages/OpsPage'), 'OpsPage');
const MitigatePage = page(() => import('@/pages/MitigatePage'), 'MitigatePage');
const WallPage = page(() => import('@/pages/WallPage'), 'WallPage');
const ContinuumPage = page(() => import('@/pages/ContinuumPage'), 'ContinuumPage');

/** Legacy/alias route #/event/:id (written in older docs) ⇒ the canonical #/events/:id, keeping ?section=. */
function EventAlias() {
  const { eventId = '' } = useParams<{ eventId: string }>();
  const { search } = useLocation();
  return <Navigate to={`/events/${encodeURIComponent(eventId)}${search}`} replace />;
}

export default function App() {
  return (
    <ThemeProvider>
      <HashRouter>
        <Routes>
          {/* Full-screen wall — no sidebar, no layout chrome */}
          <Route path="/wall" element={<Suspense fallback={null}><WallPage /></Suspense>} />
          {/* All other routes inside layout (sidebar + header) */}
          <Route path="/" element={<Layout />}>
            <Route index element={<RadarPage />} />
            <Route path="events/:eventId" element={<EventDetailPage />} />
            <Route path="event/:eventId" element={<EventAlias />} />
            <Route path="web3" element={<Web3Page />} />
            <Route path="vuln" element={<VulnPage />} />
            <Route path="continuum" element={<ContinuumPage />} />
            <Route path="sources" element={<SourcesPage />} />
            <Route path="announcements" element={<AnnouncementsPage />} />
            <Route path="search" element={<SearchPage />} />
            <Route path="subscribe" element={<SubscribePage />} />
            <Route path="ops" element={<OpsPage />} />
            <Route path="mitigate" element={<MitigatePage />} />
          </Route>
        </Routes>
      </HashRouter>
    </ThemeProvider>
  );
}
