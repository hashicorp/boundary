import styles from './section-break-cta.module.css'
import Button from '@hashicorp/react-button'

export default function SectionBreakCta({ heading, content, link }) {
  return (
    <div className={styles.sectionBreakCta}>
      <h4 className="g-type-display-4">{heading}</h4>
      <p className="g-type-body">{content}</p>
      <Button
        title={link.text}
        url={link.url}
        theme={{
          brand: 'neutral',
          variant: 'tertiary-neutral',
          background: 'light',
        }}
        linkType="inbound"
      />
    </div>
  )
}
