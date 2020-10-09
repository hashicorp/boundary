import { useEffect } from 'react'

/**
 * Hook that runs a callback on clicks outside the ref
 */
function useOnClickOutside(ref, callbackFn) {
  useEffect(() => {
    function handleClick(event) {
      const isOutside = ref.current && !ref.current.contains(event.target)
      if (isOutside) callbackFn(event)
    }

    // Bind the event listener
    document.addEventListener('mousedown', handleClick)
    return () => {
      // Unbind the event listener on clean up
      document.removeEventListener('mousedown', handleClick)
    }
  }, [ref])
}

export default useOnClickOutside
