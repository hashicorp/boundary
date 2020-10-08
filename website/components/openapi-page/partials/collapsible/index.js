import { Component } from 'react'
import styles from './collapsible.module.css'

/*
  Collapsible content block, receives children and a 'isCollapsed' prop,
  smoothly animates from collapsed (height 0) to expanded (height auto)
*/
export default class Collapsible extends Component {
  constructor(props) {
    super(props)
    this.animateHeight = this.animateHeight.bind(this)
  }

  componentDidMount() {
    this.animateHeight()
  }

  componentDidUpdate(prevProps) {
    //  Only update if isCollapsed prop has changed
    if (this.props.isCollapsed === prevProps.isCollapsed) return
    this.animateHeight()
  }

  animateHeight() {
    function handleTransitionEnd(event) {
      const elem = event.target
      const elemStyle = getComputedStyle(elem)
      const isCollapsed = elem.getAttribute('data-iscollapsed')
      if (event.propertyName !== 'height') return
      const innerElem = event.target.firstChild
      const innerElemStyle = getComputedStyle(innerElem)
      if (isCollapsed === 'false') {
        elem.style.height = 'auto'
        innerElem.style.transitionDelay = '0s'
      } else if (isCollapsed === 'true') {
        const heightDurn = parseFloat(elemStyle['transition-duration'])
        const opactiyDurn = parseFloat(innerElemStyle['transition-duration'])
        innerElem.style.transitionDelay = `${heightDurn - opactiyDurn}s`
      }
      elem.removeEventListener('transitionend', handleTransitionEnd, false)
    }
    const { isCollapsed } = this.props
    //  Do not attempt update if container elem is invalid
    const elem = this.containerRef
    if (!elem) return
    const elemStyle = getComputedStyle(elem)
    if (isCollapsed) {
      //  Transition from auto to 0
      elem.style.height = elemStyle.height
      elem.offsetHeight // force repaint
      elem.style.height = '0px'
      elem.setAttribute('data-iscollapsed', 'true')
      elem.addEventListener('transitionend', handleTransitionEnd, false)
    } else {
      //  Transition from 0 to auto
      const prevHeight = elem.style.height
      elem.style.height = 'auto'
      const endHeight = elemStyle.height
      elem.style.height = prevHeight
      elem.offsetHeight // force repaint
      elem.style.height = endHeight
      elem.setAttribute('data-iscollapsed', 'false')
      elem.addEventListener('transitionend', handleTransitionEnd, false)
    }
  }

  render() {
    const { children, noAnimation } = this.props
    return (
      <div
        className={styles.outer}
        ref={(ref) => (this.containerRef = ref)}
        data-useanimation={Boolean(!noAnimation)}
      >
        <div className={styles.inner} data-useanimation={Boolean(!noAnimation)}>
          {children}
        </div>
      </div>
    )
  }
}
