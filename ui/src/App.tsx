import { HashRouter, Routes, Route, Navigate, useParams, useLocation } from 'react-router-dom';
import { ThemeProvider } from '@/contexts/ThemeContext';
import { Layout } from '@/components/Layout';
import { RadarPage } from '@/pages/RadarPage';
import { EventDetailPage } from '@/pages/EventDetailPage';
import { Web3Page } from '@/pages/Web3Page';
import { VulnPage } from '@/pages/VulnPage';
import { SourcesPage } from '@/pages/SourcesPage';
import { OpsPage } from '@/pages/OpsPage';
import { WallPage } from '@/pages/WallPage';
import { ContinuumPage } from '@/pages/ContinuumPage';

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
          <Route path="/wall" element={<WallPage />} />
          {/* All other routes inside layout (sidebar + header) */}
          <Route path="/" element={<Layout />}>
            <Route index element={<RadarPage />} />
            <Route path="events/:eventId" element={<EventDetailPage />} />
            <Route path="event/:eventId" element={<EventAlias />} />
            <Route path="web3" element={<Web3Page />} />
            <Route path="vuln" element={<VulnPage />} />
            <Route path="continuum" element={<ContinuumPage />} />
            <Route path="sources" element={<SourcesPage />} />
            <Route path="ops" element={<OpsPage />} />
          </Route>
        </Routes>
      </HashRouter>
    </ThemeProvider>
  );
}
