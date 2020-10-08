function ChevronDownBlack({ title, ...props }) {
  return (
    <svg
      width={props.width ? props.width : props.height ? 1 * props.height : 24}
      height={props.height ? props.height : props.width ? props.width / 1 : 24}
      viewBox="0 0 24 24"
      fill="none"
      role="presentation"
      {...props}
    >
      {title ? <title>{title}</title> : null}
      <path
        d="M6 9l6 6 6-6"
        stroke={props.color || '#000'}
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

export default ChevronDownBlack
