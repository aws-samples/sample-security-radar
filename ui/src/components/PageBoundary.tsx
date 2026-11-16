import { Component, type ErrorInfo, type ReactNode } from 'react';

/** One page that throws while rendering (a value the backend added and this build does not know) shows a plain
 *  failure for that page, not a white screen for the whole site (audit 03 4.3). `resetKey` = the route: moving to
 *  another page clears the failure. */
interface Props { resetKey: string; children: ReactNode }
interface State { error: Error | null; key: string }

export class PageBoundary extends Component<Props, State> {
  state: State = { error: null, key: this.props.resetKey };

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error };
  }

  static getDerivedStateFromProps(props: Props, state: State): Partial<State> | null {
    return props.resetKey !== state.key ? { error: null, key: props.resetKey } : null;
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('page failed to render', error, info.componentStack);   // the console keeps the stack for a report
  }

  render(): ReactNode {
    if (!this.state.error) return this.props.children;
    return (
      <div className="dt-page" role="alert">
        <h1 className="dt-h2">这一页显示失败</h1>
        <p className="dt-small">页面在显示这份数据时出错（多半是数据里有这个版本的页面还不认识的值）。其他页面不受影响；刷新或稍后再试。</p>
        <p className="dt-small dt-mono">{this.state.error.message}</p>
        <a href="#/" style={{ textDecoration: 'underline' }}>← 返回态势</a>
      </div>
    );
  }
}
