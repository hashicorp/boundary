import Hero from '@hashicorp/react-hero'
import styles from './HomepageHero.module.css'

/**
 * A simple Facade around our react-hero to make the interface a little more straightforward
 * for the end-user updating this on our Homepage, while also allowing us to shim in some
 * additional styles and encapsulate that logic.
 */
export default function HomepageHero({
  title,
  description,
  links,
  uiVideo,
  cliVideo,
  desktopVideo,
}) {
  return (
    <div className={styles.homepageHero}>
      <Hero
        data={{
          product: 'boundary',
          title: title,
          description: description,
          buttons: links,
          backgroundTheme: 'light',
          centered: false,
          videos: [
            {
              name: 'UI',
              playbackRate: uiVideo.playbackRate,
              src: [
                {
                  srcType: uiVideo.srcType,
                  url: uiVideo.url,
                },
              ],
            },
            {
              name: 'CLI',
              playbackRate: cliVideo.playbackRate,
              src: [
                {
                  srcType: cliVideo.srcType,
                  url: cliVideo.url,
                },
              ],
            },
            {
              name: 'Desktop',
              playbackRate: desktopVideo.playbackRate,
              src: [
                {
                  srcType: desktopVideo.srcType,
                  url: desktopVideo.url,
                },
              ],
            },
          ],
        }}
      />
    </div>
  )
}
