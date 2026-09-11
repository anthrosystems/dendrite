import type { SVGProps } from 'react'

type Props = SVGProps<SVGSVGElement>

function Icon({ children, ...props }: Props & { children: React.ReactNode }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props}>
      {children}
    </svg>
  )
}

export const Icons = {
  overview: (props: Props) => <Icon {...props}><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="4" rx="1.5"/><rect x="14" y="11" width="7" height="10" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/></Icon>,
  activity: (props: Props) => <Icon {...props}><path d="M3 12h4l2-5 4 10 2-5h6"/></Icon>,
  incidents: (props: Props) => <Icon {...props}><path d="M12 3 2.8 19h18.4L12 3Z"/><path d="M12 9v4"/><path d="M12 16h.01"/></Icon>,
  threats: (props: Props) => <Icon {...props}><circle cx="12" cy="12" r="8"/><path d="M12 8v4l2.5 2.5"/><path d="M4.9 4.9 7 7"/><path d="M17 17l2.1 2.1"/></Icon>,
  chain: (props: Props) => <Icon {...props}><path d="M8.5 8.5 6.8 6.8a3 3 0 1 0-4.2 4.2l2.8 2.8a3 3 0 0 0 4.2 0l1-1"/><path d="m15.5 15.5 1.7 1.7a3 3 0 1 0 4.2-4.2l-2.8-2.8a3 3 0 0 0-4.2 0l-1 1"/><path d="m8.5 15.5 7-7"/></Icon>,
  memory: (props: Props) => <Icon {...props}><circle cx="7" cy="8" r="2"/><circle cx="17" cy="7" r="2"/><circle cx="12" cy="17" r="2"/><path d="m8.8 8.8 2.3 6.1"/><path d="m15.2 8.3-2.2 6.8"/><path d="M9 8h6"/></Icon>,
  topology: (props: Props) => <Icon {...props}><rect x="3" y="4" width="6" height="5" rx="1"/><rect x="15" y="4" width="6" height="5" rx="1"/><rect x="9" y="15" width="6" height="5" rx="1"/><path d="M6 9v3h12V9"/><path d="M12 12v3"/></Icon>,
  magi: (props: Props) => <Icon {...props}><circle cx="12" cy="5" r="2"/><circle cx="5" cy="18" r="2"/><circle cx="19" cy="18" r="2"/><path d="M11 7 6 16"/><path d="m13 7 5 9"/><path d="M7 18h10"/></Icon>,
  self: (props: Props) => <Icon {...props}><path d="M12 3 5 6v5c0 4.6 2.8 8 7 10 4.2-2 7-5.4 7-10V6l-7-3Z"/><path d="m9.5 12 1.6 1.6 3.5-4"/></Icon>,
  health: (props: Props) => <Icon {...props}><path d="M3 12h4l2-4 3 8 3-6 2 2h4"/></Icon>,
  chevron: (props: Props) => <Icon {...props}><path d="m9 18 6-6-6-6"/></Icon>,
  refresh: (props: Props) => <Icon {...props}><path d="M20 7v5h-5"/><path d="M4 17v-5h5"/><path d="M6.1 9a7 7 0 0 1 11.5-2.6L20 8"/><path d="M17.9 15a7 7 0 0 1-11.5 2.6L4 16"/></Icon>,
  search: (props: Props) => <Icon {...props}><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></Icon>,
}
