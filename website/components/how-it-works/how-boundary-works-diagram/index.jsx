import s from './how-boundary-works-diagram.module.css'
import classnames from 'classnames'

export default function HowBoundaryWorksDiagram({ activeExampleIndex }) {
  return (
    <div className={s.root}>
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 559.92 498.86">
        <g style={{ isolation: 'isolate' }}>
          <g id="Layer_2" data-name="Layer 2">
            <path
              d="M396.22 246.69a109.35 109.35 0 11-109.34-109.34"
              strokeDasharray="1.5 5"
              strokeWidth="1.5"
              strokeMiterlimit="10"
              strokeLinecap="round"
              stroke="var(--boundary, #ec585d)"
              fill="none"
            />

            {/* Hosts & Services */}
            <g
              className={classnames(s.hostsAndServices, {
                [s.inactive]: activeExampleIndex !== 2,
              })}
            >
              <path d="M31.92 169.08v8.4h-2.07v-3.37h-3.44v3.37h-2.07v-8.4h2.07v3.23h3.44v-3.23zM33.08 173.28a4.39 4.39 0 014.63-4.36 4.37 4.37 0 110 8.73 4.39 4.39 0 01-4.63-4.37zm7.16 0a2.53 2.53 0 10-2.53 2.53 2.43 2.43 0 002.53-2.53zM42.81 175.1l2-.58a2.35 2.35 0 002.19 1.39c.84 0 1.36-.37 1.36-.79s-.27-.6-.94-.81l-2.24-.67a2.4 2.4 0 01-2-2.22c0-1.38 1.34-2.5 3.23-2.5a4 4 0 013.85 2.2l-1.91.54a2.23 2.23 0 00-1.92-1c-.71 0-1.16.31-1.16.69s.21.49.59.6l2.19.67c1.31.4 2.39.95 2.39 2.36s-1.42 2.67-3.57 2.67a4.19 4.19 0 01-4.06-2.55zM58.18 170.88H55.4v6.6h-2.07v-6.6h-2.78v-1.8h7.63zM58.11 175.1l2-.58a2.35 2.35 0 002.26 1.39c.83 0 1.36-.37 1.36-.79s-.28-.6-.94-.81l-2.24-.67a2.42 2.42 0 01-2-2.22c0-1.38 1.35-2.5 3.23-2.5a4.08 4.08 0 013.86 2.2l-1.91.54a2.24 2.24 0 00-1.92-1c-.71 0-1.16.31-1.16.69s.21.49.58.6l2.2.67c1.31.4 2.39.95 2.39 2.36s-1.42 2.67-3.58 2.67a4.21 4.21 0 01-4.13-2.55zM75.84 177.48l-.66-.67a4.21 4.21 0 01-2.51.85 2.66 2.66 0 01-2.89-2.52 2.81 2.81 0 011.52-2.39 2.21 2.21 0 01-.6-1.41c0-1.56 1.16-2.42 2.9-2.42a2.59 2.59 0 012.69 2l-1.78.49a1 1 0 00-1-.85.79.79 0 00-.88.76c0 .37.33.67.5.87l1.92 2a4.59 4.59 0 00.45-1.14l1.75.48a5.79 5.79 0 01-.9 2l1.86 1.93zM74 175.55L72.44 174a1.21 1.21 0 00-.66 1 1 1 0 001.12.95 1.92 1.92 0 001.1-.4zM81.55 175.1l2-.58a2.33 2.33 0 002.25 1.39c.84 0 1.36-.37 1.36-.79s-.27-.6-.93-.81l-2.23-.67a2.42 2.42 0 01-2-2.22c0-1.38 1.35-2.5 3.23-2.5a4 4 0 013.85 2.2l-1.91.54a2.22 2.22 0 00-1.92-1c-.71 0-1.16.31-1.16.69s.22.49.59.6l2.19.67c1.31.4 2.4.95 2.4 2.36s-1.42 2.67-3.58 2.67a4.2 4.2 0 01-4.14-2.55zM92.37 170.88v1.47h3.91v1.74h-3.91v1.59h4.54v1.8h-6.56v-8.4h6.57v1.8zM101.71 174.72h-1.5v2.76h-2v-8.4h4.37a2.93 2.93 0 013.09 2.83 2.72 2.72 0 01-1.78 2.56l2.1 3h-2.38zm-1.5-1.74h2.17a1.13 1.13 0 001.23-1.07 1.1 1.1 0 00-1.14-1h-2.26zM115 169.08l-3.4 8.4h-2.27l-3.41-8.4h2.3l2.24 5.85 2.26-5.85zM115.77 169.08h2.09v8.4h-2.09zM119 173.28a4.37 4.37 0 014.57-4.36 4.19 4.19 0 014.28 2.81l-2 .48a2.28 2.28 0 00-2.24-1.42 2.39 2.39 0 00-2.47 2.48 2.43 2.43 0 002.47 2.51 2.25 2.25 0 002.24-1.41l2 .49a4.15 4.15 0 01-4.24 2.79 4.38 4.38 0 01-4.61-4.37zM131 170.88v1.47h3.91v1.74H131v1.59h4.54v1.8h-6.56v-8.4h6.57v1.8zM136.06 175.1l2-.58a2.35 2.35 0 002.26 1.39c.83 0 1.36-.37 1.36-.79s-.28-.6-.94-.81l-2.24-.67a2.42 2.42 0 01-2-2.22c0-1.38 1.35-2.5 3.23-2.5a4 4 0 013.85 2.2l-1.9.54a2.24 2.24 0 00-1.92-1c-.72 0-1.16.31-1.16.69s.21.49.58.6l2.2.67c1.31.4 2.39.95 2.39 2.36s-1.42 2.67-3.58 2.67a4.21 4.21 0 01-4.13-2.55z" />
              <path className={s.leadingLine} d="M156.62 129.73h.75" />
              <path
                strokeDasharray="1.62 5.39"
                className={s.leadingLine}
                d="M162.76 129.73h11.33"
              />
              <path className={s.leadingLine} d="M176.78 129.73h.75v.75" />
              <path
                strokeDasharray="1.55 5.15"
                className={s.leadingLine}
                d="M177.53 135.64v77.8"
              />
              <image
                className={s.dropShadow}
                width="75"
                height="75"
                transform="translate(10.32 94.14)"
                xlinkHref="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEsAAABLCAYAAAA4TnrqAAAACXBIWXMAAAsSAAALEgHS3X78AAAEq0lEQVR4Xu2cW3LbRhBFDylSFqnE8iup7MCL83q0OC0ikUPZepAikY+Zy2k0BgTHX0A0t2oKEESAnMPbjYFK3bOmaag6T4uhF5zS7Ou32dBrxqbm7vaX3TE7x1kOigc0JWB+ssefz4F4EpaBNHMDtz8lNWbrx0lovbAiKI15Znh4U5AFc3BDx5o+YFlYBtQcuIhj4bYXJGit0xmPcmEnOHvgNY69GQfgkAPWgWVACcgyjkvgXdwuSdC8u8YKS46ykLZu7OLxLLAWLOeoBQnQKo513AqagI49HG3ovRKgvADPwCPwFMczAZrc1grJ3NJBrloSoFwDvwHvgd/j/jr+bkkKR3v+WGSdYUPvhQDnJ/AAbAjzsOcdc5gOHp3lwm8JXJEgfQQ+xe1NPL4ihWMud41Jmvie4Kpn4AcB0nfgH+Ae+DcefyI57Ogu7ywfgisCrE/An8CXuP+eFI4Lxn1ntHdAheATwVH3hHnOSCBt7prH40A/rAsCiDUh9D4SQP0FfCa465rwRnKWzh+bFEZy1paQpzYkUK8Etyl3vdBOLUAbVi65rwghd0Nw1GfgD+ADKW/1LSHGJHsnFKx3hM+8I+SuDSH16MZl15LZMITkLCX4NSl33RBACZa9MIwTWGO2grWMx7aEHKUcrLSSNUAuDJXkc0uHawIkDcHSRacASzl2R1oKXdG9ux9z8Ozrt1lzd9ss9EO8oA1FvyjV2kpbLU4trDGrIUXAK2kOyrv2ycTOJxuGHpgcJpf5C5565BmjbKL3c9A8Tj7znvp7lnXZ3O37i04BFrQ/b/EcOrdHJ+82e2yq8nM5e25DsKxyb/J/0uDc+mCdTfstqcRZb14VVoEqrAJVWAWqsApUYRWowipQhVWgCqtAFVaBKqwCVVgFqrAKVGEVqMIqUIVVoAqrQBVWgSqsAlVYBaqwClRhFajCKlCFVaAKq0AVVoEqrAJVWAWqsApUYRWowipQhVWgCqtAFVaBKqwC9cFSrQtm++Z1rrNsGRpuf2rq++yDcxtqgtGcOaYg/1lzczg5lxwsewFbyr93Ww2Yxr9/+/n4NgWDX7qF5an7cn5b5bk1584ZfxGB5nYgfH5VqvpWBRZcB94CoLm7bWJlmHWUQKmmWJWej6R6vUumCctX26se+lh1nzm3E4YWlMr5BUgF2JfxtTumV0KnVgWqkf5BqGJVqe+OdpppAHIF5d5VctRPQlW6aqIhfBMrpuMsaMNS9f09ofr+gWAIC6wTirkErwvKVQ8kMJBKZa9oO2tKsLYEE3wH/iYBsy0KOom/Lwx1QVWpq0GE3mRNgGV7OkwBVkOqk5YR1NdhQ3KXYLV0hBWTvA1DwdLCdU94gw39DTDGCqwxW9s15JHUMUSwrLNawHLOsvQ1+QPJVSq+7q1SH6nsHdH2o9ENTD1ptqQkT28vmugubz/B0zehAvMcqLFC80sBrau0Znyh3enIrrmO6nvc0QW1rxz2TLeQfIqwbLrpXZyebAl1PJhaFwjIPDPGnqf6ZMNR0DqPP2c1G2v9st3KzsKZwt1vSI0ZkJJ5WRu7zov6u0lOFZgPy7Az0FHyLFg5TbFHqdUQmJx+GdZb1H8SnBKn/RuDWgAAAABJRU5ErkJggg=="
              />
              <image
                className={s.dropShadow}
                width="75"
                height="75"
                transform="translate(85 94.14)"
                xlinkHref="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEsAAABLCAYAAAA4TnrqAAAACXBIWXMAAAsSAAALEgHS3X78AAAEq0lEQVR4Xu2cW3LbRhBFDylSFqnE8iup7MCL83q0OC0ikUPZepAikY+Zy2k0BgTHX0A0t2oKEESAnMPbjYFK3bOmaag6T4uhF5zS7Ou32dBrxqbm7vaX3TE7x1kOigc0JWB+ssefz4F4EpaBNHMDtz8lNWbrx0lovbAiKI15Znh4U5AFc3BDx5o+YFlYBtQcuIhj4bYXJGit0xmPcmEnOHvgNY69GQfgkAPWgWVACcgyjkvgXdwuSdC8u8YKS46ykLZu7OLxLLAWLOeoBQnQKo513AqagI49HG3ovRKgvADPwCPwFMczAZrc1grJ3NJBrloSoFwDvwHvgd/j/jr+bkkKR3v+WGSdYUPvhQDnJ/AAbAjzsOcdc5gOHp3lwm8JXJEgfQQ+xe1NPL4ihWMud41Jmvie4Kpn4AcB0nfgH+Ae+DcefyI57Ogu7ywfgisCrE/An8CXuP+eFI4Lxn1ntHdAheATwVH3hHnOSCBt7prH40A/rAsCiDUh9D4SQP0FfCa465rwRnKWzh+bFEZy1paQpzYkUK8Etyl3vdBOLUAbVi65rwghd0Nw1GfgD+ADKW/1LSHGJHsnFKx3hM+8I+SuDSH16MZl15LZMITkLCX4NSl33RBACZa9MIwTWGO2grWMx7aEHKUcrLSSNUAuDJXkc0uHawIkDcHSRacASzl2R1oKXdG9ux9z8Ozrt1lzd9ss9EO8oA1FvyjV2kpbLU4trDGrIUXAK2kOyrv2ycTOJxuGHpgcJpf5C5565BmjbKL3c9A8Tj7znvp7lnXZ3O37i04BFrQ/b/EcOrdHJ+82e2yq8nM5e25DsKxyb/J/0uDc+mCdTfstqcRZb14VVoEqrAJVWAWqsApUYRWowipQhVWgCqtAFVaBKqwCVVgFqrAKVGEVqMIqUIVVoAqrQBVWgSqsAlVYBaqwClRhFajCKlCFVaAKq0AVVoEqrAJVWAWqsApUYRWowipQhVWgCqtAFVaBKqwC9cFSrQtm++Z1rrNsGRpuf2rq++yDcxtqgtGcOaYg/1lzczg5lxwsewFbyr93Ww2Yxr9/+/n4NgWDX7qF5an7cn5b5bk1584ZfxGB5nYgfH5VqvpWBRZcB94CoLm7bWJlmHWUQKmmWJWej6R6vUumCctX26se+lh1nzm3E4YWlMr5BUgF2JfxtTumV0KnVgWqkf5BqGJVqe+OdpppAHIF5d5VctRPQlW6aqIhfBMrpuMsaMNS9f09ofr+gWAIC6wTirkErwvKVQ8kMJBKZa9oO2tKsLYEE3wH/iYBsy0KOom/Lwx1QVWpq0GE3mRNgGV7OkwBVkOqk5YR1NdhQ3KXYLV0hBWTvA1DwdLCdU94gw39DTDGCqwxW9s15JHUMUSwrLNawHLOsvQ1+QPJVSq+7q1SH6nsHdH2o9ENTD1ptqQkT28vmugubz/B0zehAvMcqLFC80sBrau0Znyh3enIrrmO6nvc0QW1rxz2TLeQfIqwbLrpXZyebAl1PJhaFwjIPDPGnqf6ZMNR0DqPP2c1G2v9st3KzsKZwt1vSI0ZkJJ5WRu7zov6u0lOFZgPy7Az0FHyLFg5TbFHqdUQmJx+GdZb1H8SnBKn/RuDWgAAAABJRU5ErkJggg=="
              />
              <rect x="20.07" y="101.04" width="56" height="56" rx="3.5" />
              <rect x="92.03" y="101.04" width="56" height="56" rx="3.5" />
              <rect
                className={s.iconLines}
                x="38.37"
                y="119.34"
                width="19.4"
                height="19.4"
                rx="2.16"
              />
              <path
                className={s.iconLines}
                d="M38.37 125.8h19.4M44.83 138.73V125.8M111.51 119h16.83a2 2 0 012.13 2v4.21a2.18 2.18 0 01-2.08 2.21H111.6a2 2 0 01-2.13-2v-4.21a2.17 2.17 0 012.04-2.21zM111.67 130.64h16.84a2.09 2.09 0 012.11 2.07v4.21a2.14 2.14 0 01-2.1 2.14H111.7a2.08 2.08 0 01-2.11-2.08v-4.21a2.11 2.11 0 012.08-2.13zM116.95 134.88"
              />
            </g>

            {/* Top-right arrow segment, always active */}
            <path
              d="M395 226.76a115.51 115.51 0 00-84-88.92"
              className={s.arrowSegment}
            />

            {/* Arrow (Example 1) */}
            <g
              className={classnames(s.arrowOne, {
                [s.inactive]: activeExampleIndex !== 0,
              })}
            >
              <circle className={s.spacer} cx="367.07" cy="319.22" r="11.19" />
              <path
                className={s.arrowHead}
                d="M375.62 319.52l-11.39 3.66 2.51-11.69 8.88 8.03z"
              />
              <path
                d="M370.08 316.86a108.68 108.68 0 0023.67-47.78"
                className={s.arrowSegment}
              />
            </g>

            {/* Arrow (Example 2) */}
            <g
              className={classnames(s.arrowTwo, {
                [s.inactive]: activeExampleIndex !== 1,
              })}
            >
              <circle className={s.spacer} cx="209.12" cy="323.72" r="11.19" />
              <path
                className={s.arrowHead}
                d="M209.37 332.4l-3.1-11.56 11.56 3.09-8.46 8.47z"
              />
              <path
                d="M212.3 327a108.51 108.51 0 0046.56 26"
                className={s.arrowSegment}
              />
              <path
                className={s.arrowSegment}
                d="M307.46 355.47A115.53 115.53 0 00394 269M395 226.76a115.51 115.51 0 00-84-88.92"
              />
            </g>

            {/* Arrow (Example 3) */}
            <g
              className={classnames(s.arrowThree, {
                [s.inactive]: activeExampleIndex !== 2,
              })}
            >
              <circle className={s.spacer} cx="206.57" cy="172.98" r="11.19" />
              <path
                className={s.arrowHead}
                d="M198.03 172.68l11.39-3.67-2.52 11.7-8.87-8.03z"
              />
              <path
                d="M203.57 175.33a108.58 108.58 0 00-23.67 47.78"
                className={s.arrowSegment}
              />
              <path
                d="M396.22 246.69a109.35 109.35 0 11-187.39-76.58"
                className={s.arrowSegment}
              />
            </g>

            {/* Boundary logo */}
            <g>
              <image
                className={s.dropShadow}
                width="91"
                height="91"
                transform="translate(241.32 204.91)"
                xlinkHref="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAFsAAABbCAYAAAAcNvmZAAAACXBIWXMAAAsSAAALEgHS3X78AAAEjklEQVR4Xu2dW1LbQBBFj8FOgDzIu7KDLC7rYXHsIS+eBmOsfMw002qNLDtU+kPqUzUlIdtycXTdHvljetY0DYEP86EnbGP27fts6DljpDk/+6eEznZJtpFqBU9NuBb2tL/LBdgqW0memYHZnxqNGq2/t0nvlZ1FyzioDCt/Cmi5m8qQ49WkV2Ur0QfAYR5zsz2kSG+9nHFhy4YIfcxjncejGtWUd74glWgRusjjBfAybxcU6TbdY5ctoh/yuAdWakAR3qKVbJPoOUXwcR4neSvS5YJMoZxo0WuS5DtgCdzmcZePS9I3Ot21qZ+kekGS+gp4DbwF3uT9k/zYglJO9OvHhK3Ta1Kil8ANcAVcUhzoUjNTry/JNuVjARxRJL8HPuTtaT5+TCkntdo9JrTANSnBt8AF8Af4CfzO+1f5sRUm3TbZtoQck2R/AL4An/L+W0o5mTP+mYnIllp9B1yTPvUv8nMeSYKlhq/JMxOhT/YhSeQJqXS8J4n+CnwkpVveSJItrx8jOtkrUgm5pIiWYzeU2q1LK9CWXftyPCaVjFNSoj8Cn4F3lLrdNwUcGzrZt7RF35DkH9H+HhOn1TICJdnyBXlCqd2nJNEiW2YkU0v2Ih9fkcqJnqVZ2U/Uyoh8Sdamfq9IJ5YhsuWkU5Atzh5ITo4oiZZ7D51qZt++z5rzs2Yuf+QT6FJib2pkbi1bubnRsseMyIbyv+sbPCtaqJYRK1wSLinXJ9RjCvUaynxZfhs6NNvB34y2/Z6tU35g9u1JpyAbuv9zbfTSmZ4YbNr1saliXQxKFoZka2pvEhQG3fTJjiT/B/ZJdvBMQrYjIduRkO1IyHYkZDsSsh0J2Y6EbEdCtiMh25GQ7UjIdiRkOxKyHQnZjoRsR0K2IyHbkZDtSMh2JGQ7ErIdCdmOhGxHQrYjIduRkO1IyHYkZDsSsh0J2Y6EbEdCtiMh25GQ7UjIdiRkOxKyHQnZjoRsR0K2IyHbkZDtSMh2JGQ7ErIdCdmOhGxHQrYjfbJl0UDUNngm+yTbXoC4CG0G3QzJrp1g6pJrodvJybZFFPX6oxuzv2HPNxoBzY6jFy27drVsxwrbtUI+GVNYjs6G7dFsB0M4B2jOz5q8+K1Oswi1XStkKxdK1vaH8UrXXh5I/7/e6iCKcP1aoFtGdKLXFLlLysrneun5NdNcP1s6eCxJq8DfUaRr4Q1AX88DaPdhuSed9Jq08rkWvWLaK8NfkJxcU8Tf58drCe/UbLl6kuplPtkFZXFy8mPR8wB+kbp4XJA+9ZLwTrqhXkYk2ZLqK8rK51DW+I9uHkn0D0rLFEl3p5MH9MvWyb4klQooH6HoU9PtU3NJ6U8jsltlpNbu6oDS7+CI6MDUqK3IrnVgkvqta/emOT97SnjtC1J/XEScTHmWpJNHb7H+3mLSealVr4Fui8LomtfBzpn1bK3WNa/axA0qyc43ONC+Ovpq6iYTtVo9dtlauL671nfW7QRnotPpftj6bYcc373T6dOD0cO3j0aN1t//1MO39aToTq2xZSXtPLc79RDRd30/niU72I+/dqcU9Cr+vjoAAAAASUVORK5CYII="
              />
              <rect
                className={s.boundaryFill}
                x="251.05"
                y="211.38"
                width="72"
                height="72"
                rx="4.5"
              />
              <path
                className={s.boundaryLetter}
                d="M277.89 263.7v-2.53h5.26v-1.56h-2.55v-2.55h12.04l-5.59-9.68 5.59-9.69H280.3v13.43h-6.64v-20.07h22.85l3.81 6.61-5.61 9.72 5.73 9.91-3.7 6.41h-18.85z"
              />
              <path
                className={s.boundaryLetter}
                d="M276.37 257.06h2.55v2.55h-2.55zM273.66 261.15h2.55v2.55h-2.55z"
              />
            </g>

            {/* Users */}
            <g>
              <rect x="259.05" y="107.99" width="56" height="56" rx="3.5" />
              <path d="M274.47 89.55v4.91c0 2.15-1.38 3.66-3.88 3.66s-3.88-1.51-3.88-3.66v-4.91h2.1v4.87a1.78 1.78 0 103.56 0v-4.87zM275.31 95.57l2-.58a2.35 2.35 0 002.26 1.39c.83 0 1.36-.37 1.36-.79s-.28-.6-.94-.81l-2.24-.67a2.42 2.42 0 01-2-2.22c0-1.38 1.35-2.5 3.23-2.5a4 4 0 013.85 2.2l-1.9.54a2.24 2.24 0 00-1.92-1c-.71 0-1.16.31-1.16.69s.21.49.58.6l2.2.67c1.31.4 2.39 1 2.39 2.36s-1.42 2.67-3.58 2.67a4.21 4.21 0 01-4.13-2.55zM286.13 91.35v1.47h3.92v1.74h-3.92v1.59h4.54V98h-6.56v-8.4h6.57v1.8zM295.47 95.19H294V98h-2v-8.4h4.36a2.92 2.92 0 013.09 2.83 2.72 2.72 0 01-1.78 2.56l2.11 3h-2.38zM294 93.45h2.17a1.13 1.13 0 001.24-1.07 1.11 1.11 0 00-1.15-1H294zM300 95.57l2-.58a2.34 2.34 0 002.25 1.39c.84 0 1.36-.37 1.36-.79s-.27-.6-.93-.81l-2.24-.67a2.42 2.42 0 01-2-2.22c0-1.38 1.35-2.5 3.23-2.5a4 4 0 013.85 2.2l-1.91.54a2.22 2.22 0 00-1.92-1c-.71 0-1.16.31-1.16.69s.22.49.59.6l2.2.67c1.3.4 2.39 1 2.39 2.36s-1.42 2.67-3.58 2.67a4.2 4.2 0 01-4.13-2.55z" />
              <path
                className={s.iconLines}
                d="M292.05 146v-2a4 4 0 00-4-4h-8a4 4 0 00-4 4v2"
              />
              <circle className={s.iconLines} cx="284.05" cy="131.99" r="4" />
              <path
                className={s.iconLines}
                d="M298.05 146v-2a4 4 0 00-3-3.87M291.05 128.12a4 4 0 010 7.75"
              />
              <path
                className={s.subtitle}
                d="M38 251.51h3.15a4.22 4.22 0 01.12 8.42H38zm3.1 7.36a3 3 0 003-3.18 2.88 2.88 0 00-3-3.15h-2.09v6.33zM46.33 261.35h.51a1.21 1.21 0 001.16-.85l.37-1-2.44-5.63h1.18l1.81 4.36 1.73-4.36h1.19l-2.79 6.82a2.12 2.12 0 01-2.15 1.57h-.57zM52.86 253.91h1.07v.8a2.36 2.36 0 014.25 1.51v3.68h-1.13v-3.6c0-1.08-.6-1.63-1.41-1.63a1.84 1.84 0 00-1.71 2.07v3.16h-1.07zM59.5 258.21a1.57 1.57 0 01.58-1.28 3.22 3.22 0 011.69-.54c.8-.07 1.83-.16 1.83-.82s-.53-.88-1.24-.88a1.36 1.36 0 00-1.51 1.1h-1.12a2.38 2.38 0 012.58-2c1.53 0 2.4.87 2.4 2v4.1H63.6v-.8a2.52 2.52 0 01-2 .92 1.91 1.91 0 01-2.1-1.8zm4.1-.68v-.71a3.7 3.7 0 01-1.61.37c-.93.09-1.36.42-1.36 1s.5.93 1.12 1a1.67 1.67 0 001.85-1.66zM66.41 253.91h1.07v.8a2.12 2.12 0 011.84-1 2.27 2.27 0 012 1.19 2.42 2.42 0 012.15-1.19 2.27 2.27 0 012.34 2.47v3.68H74.7v-3.6c0-1.08-.59-1.63-1.41-1.63s-1.63.79-1.63 2.07v3.16h-1.14v-3.6c0-1.08-.58-1.63-1.41-1.63s-1.63.79-1.63 2.07v3.16h-1.07zM77.53 251.51h1.21v1.27h-1.21zm0 2.4h1.17v6h-1.12zM80.06 256.9a2.9 2.9 0 012.94-3.11 2.51 2.51 0 012.64 2.09h-1.1a1.55 1.55 0 00-1.54-1.19c-1 0-1.78.83-1.78 2.18s.76 2.18 1.78 2.18a1.53 1.53 0 001.57-1.2h1.1A2.58 2.58 0 0183 260a2.87 2.87 0 01-2.94-3.1zM89.78 257.31H91a2.08 2.08 0 002.36 1.69c1.22 0 1.89-.65 1.89-1.45s-.48-1.18-1.88-1.37C90.9 255.85 90 255 90 253.79s1.28-2.36 3-2.36c2 0 3.24 1 3.29 2.67h-1.16c-.08-1.06-.91-1.63-2.11-1.63s-1.77.62-1.77 1.28.85 1.2 2 1.37c2.43.32 3.19 1.15 3.19 2.43 0 1.49-1.31 2.44-3.18 2.44s-3.34-.88-3.48-2.68zM97.5 257a2.85 2.85 0 012.91-3.12c1.82 0 2.86 1.44 2.77 3.39h-4.56a1.73 1.73 0 001.82 1.89 1.66 1.66 0 001.63-1.12h1a2.5 2.5 0 01-2.65 2A2.81 2.81 0 0197.5 257zm4.53-.66a1.54 1.54 0 00-1.65-1.54 1.62 1.62 0 00-1.72 1.54zM104.14 256.9a2.9 2.9 0 012.94-3.11 2.51 2.51 0 012.64 2.09h-1.09a1.56 1.56 0 00-1.57-1.19c-1 0-1.79.83-1.79 2.18s.77 2.18 1.79 2.18a1.54 1.54 0 001.57-1.2h1.09A2.58 2.58 0 01107 260a2.87 2.87 0 01-2.86-3.1zM111.12 253.91h1v.78a1.85 1.85 0 011.88-.88h.17v1h-.12c-1 0-1.93.33-1.93 1.78v3.25h-1zM114.72 257a2.86 2.86 0 012.92-3.12c1.82 0 2.86 1.44 2.77 3.39h-4.56a1.73 1.73 0 001.82 1.89 1.66 1.66 0 001.63-1.16h1a2.51 2.51 0 01-2.66 2 2.81 2.81 0 01-2.92-3zm4.54-.66a1.54 1.54 0 00-1.66-1.54 1.62 1.62 0 00-1.72 1.54zM121.83 258.34v-3.55h-1v-.88h1v-1.82h1v1.82h1.53v.88h-1.53v3.36c0 .59.23.82.77.82h.78v.93h-1a1.49 1.49 0 01-1.55-1.56zM125.07 258h1.05a1.44 1.44 0 001.58 1.17c.87 0 1.27-.47 1.27-1s-.32-.75-1.32-.91c-1.94-.27-2.39-1-2.39-1.76s.91-1.69 2.23-1.69a2.18 2.18 0 012.45 2h-1a1.26 1.26 0 00-1.42-1.14c-.61 0-1.18.3-1.18.8s.46.74 1.32.86c1.81.26 2.43.82 2.43 1.8S129 260 127.7 260s-2.56-.65-2.63-2zM213.77 429.35l3.34-8.38h1.15l3.34 8.39h-1.25l-.86-2.21h-3.61l-.86 2.21zm5.4-3.19l-1.49-3.91-1.48 3.91zM222.05 423.36h1.14L225 428l1.82-4.68H228l-2.49 6h-1zM228.48 427.67a1.58 1.58 0 01.57-1.28 3.26 3.26 0 011.7-.54c.8-.07 1.83-.16 1.83-.82s-.53-.89-1.25-.89a1.36 1.36 0 00-1.5 1.11h-1.13a2.37 2.37 0 012.58-2c1.54 0 2.41.86 2.41 2v4.1h-1.11v-.8a2.54 2.54 0 01-2 .92 1.91 1.91 0 01-2.1-1.8zm4.1-.68v-.71a3.6 3.6 0 01-1.6.37c-.93.08-1.36.42-1.36 1s.5.92 1.12.95a1.68 1.68 0 001.84-1.6zM235.32 421h1.21v1.27h-1.21zm.05 2.39h1.13v6h-1.13zM238.29 421h1.11v8.39h-1.11zM240.78 427.67a1.56 1.56 0 01.58-1.28 3.22 3.22 0 011.69-.54c.8-.07 1.83-.16 1.83-.82s-.53-.89-1.24-.89a1.38 1.38 0 00-1.51 1.11H241a2.37 2.37 0 012.58-2c1.53 0 2.4.86 2.4 2v4.1h-1.11v-.8a2.51 2.51 0 01-2 .92 1.91 1.91 0 01-2.09-1.8zm4.1-.68v-.71a3.7 3.7 0 01-1.61.37c-.92.08-1.36.42-1.36 1s.5.92 1.12.95a1.68 1.68 0 001.85-1.6zM248.72 428.45v.91h-1V421h1v3.37a2.4 2.4 0 012.1-1 2.86 2.86 0 012.79 3.1 2.9 2.9 0 01-2.83 3.09 2.42 2.42 0 01-2.06-1.11zm3.74-2.1a1.89 1.89 0 00-1.84-2.1 2 2 0 00-1.91 2.2 1.9 1.9 0 001.91 2.07 1.93 1.93 0 001.84-2.17zM255 421h1.11v8.39H255zM257.49 426.41a2.85 2.85 0 012.91-3.12c1.82 0 2.86 1.44 2.77 3.38h-4.56a1.73 1.73 0 001.82 1.89 1.66 1.66 0 001.63-1.13h1a2.49 2.49 0 01-2.65 2 2.81 2.81 0 01-2.92-3.02zm4.53-.66a1.55 1.55 0 00-1.65-1.55 1.63 1.63 0 00-1.72 1.55zM267.93 421h1.16v3.63h4.4V421h1.16v8.39h-1.16v-3.81h-4.4v3.81h-1.16zM276.16 426.36a2.92 2.92 0 013-3.08 3.07 3.07 0 11-3 3.08zm4.86 0a1.89 1.89 0 00-1.89-2.13 2.12 2.12 0 101.89 2.13zM283 427.44h1a1.45 1.45 0 001.59 1.17c.87 0 1.27-.47 1.27-1s-.33-.75-1.32-.91c-1.95-.28-2.4-1-2.4-1.76s.91-1.69 2.24-1.69a2.18 2.18 0 012.45 2h-1a1.26 1.26 0 00-1.42-1.14c-.61 0-1.18.3-1.18.8s.46.74 1.32.86c1.8.26 2.43.82 2.43 1.8s-1.07 1.87-2.38 1.87-2.6-.63-2.6-2zM289.32 427.8v-3.55h-1v-.89h1v-1.81h1.05v1.81h1.53v.89h-1.53v3.36c0 .59.24.82.77.82h.79v.93h-1a1.49 1.49 0 01-1.61-1.56zM292.56 427.44h1.05a1.45 1.45 0 001.59 1.17c.87 0 1.27-.47 1.27-1s-.33-.75-1.32-.91c-1.95-.28-2.4-1-2.4-1.76s.91-1.69 2.23-1.69a2.19 2.19 0 012.46 2h-1a1.26 1.26 0 00-1.42-1.14c-.61 0-1.19.3-1.19.8s.47.74 1.33.86c1.8.26 2.43.82 2.43 1.8s-1.08 1.87-2.38 1.87-2.57-.63-2.65-2zM302.08 427.23a2.75 2.75 0 011.59-2.44 3.11 3.11 0 01-1-2 2.1 2.1 0 012.2-2 2 2 0 012.14 1.94 2.68 2.68 0 01-1.71 2.22l1.79 1.71.51-.87h1.3l-1 1.66 2 1.89h-1.48l-1.1-1.05a3.12 3.12 0 01-2.53 1.22 2.49 2.49 0 01-2.71-2.28zm4.47.32l-2.17-2c-.81.44-1.23 1-1.23 1.61a1.48 1.48 0 001.62 1.38 2.19 2.19 0 001.78-.99zm-.55-4.77a1 1 0 00-1.09-1 1.1 1.1 0 00-1.13 1 2.12 2.12 0 00.83 1.5c.79-.38 1.39-.94 1.39-1.5zM314.52 426.77h1.24a2.09 2.09 0 002.33 1.67c1.23 0 1.9-.65 1.9-1.45s-.49-1.18-1.88-1.37c-2.47-.31-3.36-1.19-3.36-2.37s1.29-2.36 3-2.36c2 0 3.24 1 3.29 2.67h-1.18c-.07-1.06-.91-1.63-2.1-1.63s-1.77.62-1.77 1.28.85 1.2 2 1.37c2.43.32 3.19 1.15 3.19 2.43 0 1.49-1.31 2.44-3.18 2.44s-3.35-.88-3.48-2.68zM322.23 426.41a2.85 2.85 0 012.92-3.12c1.82 0 2.86 1.44 2.77 3.38h-4.57a1.73 1.73 0 001.83 1.89 1.66 1.66 0 001.63-1.13h1a2.51 2.51 0 01-2.66 2 2.81 2.81 0 01-2.92-3.02zm4.54-.66a1.55 1.55 0 00-1.66-1.55 1.63 1.63 0 00-1.72 1.55zM329.31 423.36h1.05v.78a1.87 1.87 0 011.88-.87h.18v1h-.13c-1 0-1.93.34-1.93 1.79v3.25h-1.05zM332.92 423.36h1.14l1.85 4.68 1.82-4.68h1.17l-2.49 6h-1zM339.85 421h1.21v1.27h-1.21zm0 2.39H341v6h-1.1zM342.38 426.36a2.9 2.9 0 012.94-3.11 2.51 2.51 0 012.64 2.09h-1.1a1.55 1.55 0 00-1.57-1.2c-1 0-1.78.84-1.78 2.19s.76 2.18 1.78 2.18a1.53 1.53 0 001.57-1.2H348a2.58 2.58 0 01-2.69 2.14 2.87 2.87 0 01-2.93-3.09zM348.92 426.41a2.85 2.85 0 012.92-3.12c1.82 0 2.85 1.44 2.77 3.38H350a1.73 1.73 0 001.82 1.89 1.66 1.66 0 001.64-1.13h1a2.51 2.51 0 01-2.66 2 2.81 2.81 0 01-2.88-3.02zm4.54-.66a1.55 1.55 0 00-1.66-1.55 1.63 1.63 0 00-1.72 1.55zM355.5 427.44h1.05a1.44 1.44 0 001.58 1.17c.88 0 1.28-.47 1.28-1s-.33-.75-1.33-.91c-1.94-.28-2.39-1-2.39-1.76s.91-1.69 2.23-1.69a2.19 2.19 0 012.46 2h-1a1.26 1.26 0 00-1.42-1.14c-.61 0-1.19.3-1.19.8s.46.74 1.32.86c1.81.26 2.43.82 2.43 1.8s-1.07 1.87-2.38 1.87-2.56-.63-2.64-2z"
              />
            </g>

            {/* Authenticate */}
            <g className={s.authenticate}>
              <image
                className={s.dropShadow}
                width="75"
                height="75"
                transform="translate(363.32 212.91)"
                xlinkHref="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEsAAABLCAYAAAA4TnrqAAAACXBIWXMAAAsSAAALEgHS3X78AAAD+0lEQVR4Xu2cW1LbQBBFj41t3iEEKllCFpf1sDj2kJd5GtugfMw00xqNLHXyEQn6VnVJth5UH26PZYruSVVVuPpp1nVCmyZfv026zhmqquurv3LIpI+zMjBt+2ORTvh1vw/AnbAiJB0UXo9RlYra613QirCUk6YEKNNCaHhjkYbzUgh5v+i0BqzMTXsqZjHktQAbelnmZSdAnmNsYzyrKLqsbYEXUDNgoWIfmMfQwPR1Q1MOS0BtYjwBaxWQgNVUc1Z01ZQEah84AI5iHMbX+ySX5cCGKg1qS4C0Ah6Bhxir+L447UW7K3eWLr8FAcwJ8CHGKXBMgDaP1w99/crXqS3BUY/APXAL3BDykPPk3Im6Pjkrc9WC4KRT4CNwDlzE/bN47IA6rCGCEmkAW4KDHoAl8Bv4AfyK+7fx2JrMXSVnTUlr1RHBURfAZ+CSAO6EAEvWrrHAkrVqBdwRqmQRz3kmAJI1bEv8ZBSVFniBtU8oN3HXJfAF+EQAeEj4QWNz1ppQgjckUPLePWntkrJ8lYYlCUspzgnuOSaU3jkB1CWpFLWzhi7trAfqoO4J8HS1aBPsLEOBJe46Ii30ZzHG7Kx5fH9NKEf5pJdHo+Kn/AxeF3doumtGctgBCZxs54wPlhhkQ3oUEkflj0MTCHyq66sqL0O9r4EJtEW21bCGLoEFzTz0t5PSg3axDOWgdpjEXrYtfU8csuR5qSsfnX9NXX/PmhhiDOrKYWcejY/HFuU367zxgFXKo1cubbDyG74HdRqhr7NcOCyTHJZBDssgh2WQwzLIYRnksAxyWAY5LIMclkEOyyCHZZDDMshhGeSwDHJYBjksgxyWQQ7LIIdlkMMyyGEZ5LAMclgGOSyDHJZBDssgh2WQwzLIYRnksAxyWAY5LIMclkEOy6A2WNKRgNq+del8izn3dVZFE+BYIZby6JVLV9NA1TPGoK4cOnMpwdIX6jb+52wrAeP4X/m++bSC07D0QbmxbuXfEFrOZCvXTjF0Kfwn6V9+nseG+rgCAaavBWLC1fVVFdvo9E0FlLTJ6k516dcba7+h5PFIyk2gaWAVQFuPtAYlMw/kxnfUW2U3jLuTdUnI544E7ikeLzmsUYY5rBWhJXZJvfl6zbg7WaVH+ieh635JyFMc1nAXlBd4aecXV92SwEBqlX0L3fe/gO+kEQXirkbnPbSX4ZYA5YHwG9iLx6X5+i3OdbghzXMQWLUyzMerTAnJ62by9zIxRNYvvXa9VNdXrw4rOUvsuiYlL7V+z9ufRSOTQmrrFdA6EmrK+51yVBzaA+1fd8Rdsi9r2Ir3Mz+rIZ/M1vyq8wL0m8xWO+gz/2ryaZKy86/TJHfJ55S6duoPpB8K5VDMD2sAAAAASUVORK5CYII="
              />
              <rect x="372.79" y="219.38" width="56" height="56" rx="3.5" />

              <path d="M446.67 240.64H443l-.61 1.61h-2.13l3.23-8.4h2.71l3.23 8.4h-2.13zm-.67-1.74l-1.18-3.14-1.19 3.14zM457.54 233.85v4.91c0 2.15-1.37 3.66-3.88 3.66s-3.87-1.51-3.87-3.66v-4.91h2.09v4.87a1.79 1.79 0 103.57 0v-4.87zM466 235.65h-2.78v6.6h-2.07v-6.6h-2.78v-1.8H466zM474.56 233.85v8.4h-2.07v-3.37h-3.44v3.37H467v-8.4h2.07v3.23h3.44v-3.23zM478.07 235.65v1.47H482v1.73h-3.92v1.6h4.54v1.8h-6.56v-8.4h6.57v1.8zM491.55 233.85v8.4h-1.69l-3.92-4.81v4.81h-2.07v-8.4h1.68l3.93 4.81v-4.81zM500.11 235.65h-2.78v6.6h-2.07v-6.6h-2.78v-1.8h7.63zM501.05 233.85h2.09v8.4h-2.09zM504.3 238.05a4.37 4.37 0 014.57-4.36 4.19 4.19 0 014.28 2.81l-2 .48a2.28 2.28 0 00-2.24-1.42 2.39 2.39 0 00-2.47 2.48 2.43 2.43 0 002.47 2.51 2.25 2.25 0 002.24-1.41l2 .49a4.15 4.15 0 01-4.24 2.79 4.39 4.39 0 01-4.61-4.37zM519.64 240.64H516l-.61 1.61h-2.13l3.23-8.4h2.72l3.23 8.4h-2.13zm-.64-1.74l-1.18-3.14-1.18 3.14zM529.14 235.65h-2.78v6.6h-2.07v-6.6h-2.78v-1.8h7.63zM532.1 235.65v1.47h3.9v1.73h-3.9v1.6h4.54v1.8h-6.56v-8.4h6.57v1.8z" />
              <path
                className={s.subtitle}
                d="M441.34 250.51h1.13v8.39h-1.13zM444 255.94a2.85 2.85 0 012.79-3.09 2.44 2.44 0 012.1 1v-3.37h1v8.39h-1V258a2.43 2.43 0 01-2.06 1 2.9 2.9 0 01-2.83-3.06zm4.9.05a2 2 0 00-1.92-2.2 1.9 1.9 0 00-1.85 2.1 1.94 1.94 0 001.85 2.17 1.91 1.91 0 001.96-2.06zM451.35 256a2.85 2.85 0 012.91-3.12c1.82 0 2.86 1.44 2.77 3.39h-4.56a1.73 1.73 0 001.82 1.89 1.66 1.66 0 001.63-1.12h1a2.5 2.5 0 01-2.66 2 2.81 2.81 0 01-2.91-3.04zm4.53-.66a1.54 1.54 0 00-1.66-1.54 1.63 1.63 0 00-1.72 1.54zM458.43 252.91h1.07v.8a2.36 2.36 0 014.25 1.51v3.68h-1.14v-3.6c0-1.08-.59-1.63-1.4-1.63a1.84 1.84 0 00-1.71 2.07v3.16h-1.07zM465.53 257.34v-3.55h-1v-.88h1v-1.82h1.05v1.82h1.53v.88h-1.53v3.36c0 .59.23.82.77.82h.79v.93h-1a1.49 1.49 0 01-1.61-1.56zM469.21 250.51h1.21v1.27h-1.21zm.05 2.4h1.12v6h-1.12zM472.2 257.34v-3.55h-1v-.88h1v-1.82h1.05v1.82h1.53v.88h-1.53v3.36c0 .59.23.82.77.82h.79v.93h-1a1.49 1.49 0 01-1.61-1.56zM475.51 260.35h.49a1.21 1.21 0 001.17-.85l.37-1-2.44-5.63h1.18l1.81 4.36 1.73-4.36H481l-2.79 6.82a2.12 2.12 0 01-2.15 1.57h-.57zM485.41 250.51H489a2.49 2.49 0 11-.07 5h-2.43v3.43h-1.09zm3.37 4a1.52 1.52 0 001.69-1.55 1.55 1.55 0 00-1.69-1.58h-2.28v3.13zM492.81 252.91h1v.78a1.85 1.85 0 011.88-.88h.18v1h-.13c-1 0-1.93.33-1.93 1.78v3.25h-1zM496.41 255.9a3 3 0 113 3.06 2.92 2.92 0 01-3-3.06zm4.86 0a1.9 1.9 0 10-1.91 2.08 1.89 1.89 0 001.91-2.06zM502.78 252.91h1.14l1.85 4.67 1.82-4.67h1.17l-2.49 6h-1zM509.71 250.51h1.21v1.27h-1.21zm.05 2.4h1.12v6h-1.12zM512.24 255.94a2.85 2.85 0 012.79-3.09 2.44 2.44 0 012.1 1v-3.37h1v8.39h-1V258a2.43 2.43 0 01-2.06 1 2.9 2.9 0 01-2.83-3.06zm4.9.05a2 2 0 00-1.92-2.2 1.9 1.9 0 00-1.85 2.1 1.94 1.94 0 001.85 2.17 1.91 1.91 0 001.92-2.06zM519.54 256a2.86 2.86 0 012.92-3.12c1.82 0 2.86 1.44 2.77 3.39h-4.56a1.73 1.73 0 001.82 1.89 1.66 1.66 0 001.63-1.12h1a2.51 2.51 0 01-2.66 2 2.81 2.81 0 01-2.92-3.04zm4.54-.66a1.54 1.54 0 00-1.66-1.54 1.62 1.62 0 00-1.72 1.54zM526.62 252.91h1v.78a1.85 1.85 0 011.88-.88h.18v1h-.13c-1 0-1.93.33-1.93 1.78v3.25h-1z"
              />
              <path
                className={s.iconLines}
                d="M389.93 255.31a3.74 3.74 0 013.73-3.74 3.74 3.74 0 013.74 3.74v1.49h-7.47z"
              />
              <path
                className={s.iconLines}
                d="M396.27 241.33h-7.64a1.84 1.84 0 00-1.84 1.84V255a1.84 1.84 0 001.84 1.84h22.11a1.84 1.84 0 001.84-1.84v-11.83a1.84 1.84 0 00-1.84-1.84h-7.63"
              />
              <path
                className={s.iconLines}
                d="M400.64 246.42h8.43M400.64 249.94h3.29M407.53 249.94h1.54"
              />
              <circle
                className={s.iconLines}
                cx="393.66"
                cy="248.21"
                r="3.37"
              />
              <path
                className={s.iconLines}
                d="M394.78 238h9.82v2.46l-4.91 3.07-4.91-3.07z"
              />
            </g>

            {/* Authorize */}
            <g
              className={classnames(s.authorize, {
                [s.inactive]: activeExampleIndex === 0,
              })}
            >
              <path d="M256.85 408.79h-3.69l-.62 1.61h-2.13l3.23-8.4h2.72l3.23 8.4h-2.13zm-.67-1.74l-1.18-3.14-1.18 3.14zM267.72 402v4.91c0 2.14-1.38 3.65-3.88 3.65s-3.88-1.51-3.88-3.65V402h2.1v4.87a1.78 1.78 0 103.56 0V402zM276.22 403.8h-2.78v6.6h-2.07v-6.6h-2.78V402h7.63zM284.73 402v8.4h-2.07V407h-3.44v3.37h-2.07V402h2.07v3.23h3.44V402zM285.89 406.2a4.63 4.63 0 114.62 4.36 4.39 4.39 0 01-4.62-4.36zm7.16 0a2.54 2.54 0 10-2.54 2.53 2.43 2.43 0 002.54-2.53zM299.84 407.64h-1.5v2.76h-2V402h4.36a2.92 2.92 0 013.09 2.83 2.7 2.7 0 01-1.78 2.55l2.11 3h-2.42zm-1.5-1.74h2.17a1.13 1.13 0 001.24-1.07 1.1 1.1 0 00-1.15-1.05h-2.26zM305.07 402h2.1v8.4h-2.1zM315.5 408.63v1.77h-7.21v-1.34l4.24-5.3h-4.18V402h7v1.36l-4.2 5.27zM318.64 403.8v1.46h3.91V407h-3.91v1.6h4.54v1.8h-6.56V402h6.57v1.8z" />
              <path className={s.spacer} d="M252.67 324.28h68.6v66.62h-68.6z" />
              <image
                className={s.dropShadow}
                width="75"
                height="75"
                transform="translate(249.32 322.91)"
                xlinkHref="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEsAAABLCAYAAAA4TnrqAAAACXBIWXMAAAsSAAALEgHS3X78AAAEVElEQVR4Xu2cW1LbQBBFj41tHnmQBCpZQhaX9bA4FpEnYDvGRvmYaaY1Glnq/EQT+lZ1SbZkQR9uj+RUumdN0+Aap8XQCX2aff4yGzpnqmpub/7KIbMxzsrA9O3XIp3w8/4YgEdhRUg6KLyuUY2K1utj0IqwlJPmBCjzQmh4tUjDeSqEvF90WgdW5qYTFYsY8lqATb0s87ITIIcY+xgHFUWX9S3wAmoBrFScAssYGpj+3NSUwxJQjzF+AzsVkIC11HJWdNWcBOoUOAMuYpzH16ckl+XApioNak+AtAU2wDrGNr4vTnvS7sqdpctvRQDzGngb4w3wigBtGT8/9fUrX6f2BEdtgAfgDvhFyEPOk3Nn6vPJWZmrVgQnvQHeAe+Bq7h/GY+d0YY1RVAiDWBPcNAa+An8AL4C3+P+XTy2I3NXyVlz0lp1QXDUFfARuCaAe02AJWtXLbBkrdoC94QqWcVzDgRAsobtiXdGUWmBF1inhHITd10Dn4APBIDnhB9Um7N2hBL8RQIl7z2Q1i4py2dpWJKwlOKS4J5XhNJ7TwB1TSpF7aypSztrTRvUAwGerhZtgqNlKLDEXRekhf4yRs3OWsb3d4RylDu9PBoV7/ILeF7coeuuBclhZyRwsl1SHywxyCPpUUgclT8OzSDwaW5vmrwM9b4GJtBW2VbDmroEFnTz0N9OSg/axTKUg9phEifZtvQ9ccqS56WhfHT+LQ39e9bMEDVoKIejeXRujz3KLzZ44QmrlMeoXPpg5Rd8CRo0wlhnuXBYJjksgxyWQQ7LIIdlkMMyyGEZ5LAMclgGOSyDHJZBDssgh2WQwzLIYRnksAxyWAY5LIMclkEOyyCHZZDDMshhGeSwDHJYBjksgxyWQQ7LIIdlkMMyyGEZ5LAMclgGOSyDHJZBfbCkIwG1ffEa66yGLsBaIfb97oO5DTUNNCOjBuW/aymHo7mUYOkL6Db+Q7aVgDr+r3yeTz6iYPCPrmHl1HXztfQV79RWPjvH0KXwjyS5PZG67vcqZESBBteBtwBobm+a2EanHSWgpE1Wd6pLv15N/YaQYG1ibEkjCjS43DhAtww1KJl5IIDuabfKPlJfJ6s0lG8IjeP3hC7WDSHXR9rLTANQaijPXSWOeiB0qevm6x11dbJCG5Y0lOcd9xpYpxRLC7xcUFx1RwIDqVW2pu57aMOSvmgZUyDANrQ771vA+spQLrgmlN5JPC4/pLa5DpASl5EEYoQfwDdCnuKuzpgCULDiIq/LUGDJg+uB1OJf08QQSO4QWFI5a9LEEIGlndUCVnKWpi/JP5FcVfMsGkiVk9/A1qQylEWe3lk00V25/QSe/CVqm3IE3UcBea6SZ0Y96UjfEQcXeEgXlH1Zw7bUNz8LurD0ctP7cJrPz3ppk9mgXY4CrfP1Z9RkttbB/3fmHySHaXjQAwoGYD2f9H9Nk4RuWYadgYmSo2CVVPOcUhgGU9Jfw3qJ+gOPxgR0lfraPQAAAABJRU5ErkJggg=="
              />
              <rect
                className={s.iconBg}
                x="259.55"
                y="330.14"
                width="55"
                height="55"
                rx="3"
              />

              <path
                className={s.iconLines}
                d="M280 365.09a2.5 2.5 0 012.5-2.5H296"
              />
              <path
                className={s.iconLines}
                d="M282.46 347.59H296v20h-13.5a2.5 2.5 0 01-2.5-2.5v-15a2.5 2.5 0 012.46-2.5zM278.13 352.47h4.71M278.13 356.47h4.71"
              />
            </g>

            {/* Access */}
            <g
              className={classnames(s.access, {
                [s.inactive]: activeExampleIndex !== 2,
              })}
            >
              <path className={s.spacer} d="M140.24 213.11h68.6v66.62h-68.6z" />
              <image
                className={s.dropShadow}
                width="75"
                height="75"
                transform="translate(137.32 212.91)"
                xlinkHref="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEsAAABLCAYAAAA4TnrqAAAACXBIWXMAAAsSAAALEgHS3X78AAAEWklEQVR4Xu2cW1LjSBBFj93G0PRrepqYWQKLYz0sjj3Mo7sxxg9szUdWulLlElbOl6vJG5FRkmwJ5+FmSSbImnRdR2icZqfeMKTJ7d3k1HvOWd3DvdslkzHOKsAMbbckm/Rh+xTAV2ElSDao7LeqzgTAXo8PQavCMk6aIlCmlbDwWpKF06WxjCqwI1iFm96ZmKXQfQXWQlmWZaeQdsCLiV2KPbAvgQ1N8ApqBsxNXAIXKSwwe945qoSlULbABlincZOOvQDd5PauN4/1YCVXTcmgLoEr4DrF+7R/SXZZCexcZcvvBYGyBp6BZYqpea+6rw6LfvnNETAfgc8pPgEfEGgX6fwW5q/OjFp6awTQI/ATyRlyee6B/eT2bqLuOsAyc5U6a4646TPwFfgG/AZ8Scev6MM6V1AqdcsOKbdnBNR35BcPuTS3aXuaRqDurCl5rlJY34A/gBsE3EcEls5drcDSEtwATwioeXpdy3KVxm15gdoEr7AukXL7hDjqBvgT+B0B+B75QS05S2GtgAWSIwi8ZTo257hi+mVoXtAyvEDc8wEpva8IqBtyKVpnnbssrGcyqDUC6Zp8t69Wy1AZKix11zV5ov+SoiVn2TvhljxHrck3LAuq9+Ctk/xMd9LJpbtmZIddkcHpeEF7sNQgWyQnfYa0D902l8EytNsWmEKbF6OFde7SMgQpxRl9QOW3kqOcahO8fbP9LviuGGvfE89Z6q7ys4+ujFN/z5o4ogWV1VN+/lfzmDJOtYu2AqjU0Gc/mdsQrNG035LGOitEwHIpYDkUsBwKWA4FLIcClkMBy6GA5VDAcihgORSwHApYDgUshwKWQwHLoYDlUMByKGA5FLAcClgOBSyHApZDAcuhgOVQwHIoYDkUsBwKWA4FLIcClkMBy6GA5VDAcihgORSwHBqCpe1mmPFXl823mvNYZ3UcA2wVYi2PUbmcahroRkYLOpXDyVxqsOyJtn1/V4wa0Mb/yo/NZxCchWVf1AvbVn7tVNdRz51y/h0X9pdf5qHd9rpUQa+J3G7PALqH+y610dmLKqgt0vm5Ineqa79eS/2Gmpf2Ry/TqLkpNAusAzhqKDcXVVBlK/8C6VK3PcWtdbJqXkvgB5LPggxOe6NrDjsqwxLWCmm8/oF0fCqoDe11spbO+gn8A/yL5PdEdtiRu6A+wWsfsbrqkQwG5IctaKv7XpO2JlggoP5CuvAfye56Id+8DhoqQ23nX9JfIEJb/Ftb18E6S7vvtRS/A38jeS6RHBVWrwx7C/dMbu+mSPK2mbz1FUM6MyqsLeKiJ/KKITp/2blr3z3cHxxWc5badUNOXmv9ibbXorF3eV3wwq5Fs0Ly3FHMV8DgklBTfp1VjmyC5Q1M7/gbE4fHh7FLQqm7dFvnsBXtrZ9VwrLA7EP3zkTfQUlvbWW2cv4qQ49X1/97q2v+dSZ6+68tkvgWV5Msy1I2RizFOQpWTS2vUzoGTE3/G9Zb1H9jnvZy1NR71wAAAABJRU5ErkJggg=="
              />
              <path d="M84.62 239.64h-3.69l-.61 1.61h-2.13l3.22-8.4h2.72l3.23 8.4h-2.13zM84 237.9l-1.19-3.14-1.18 3.14zM87.34 237.05a4.37 4.37 0 014.57-4.36 4.2 4.2 0 014.28 2.81l-2 .48a2.29 2.29 0 00-2.25-1.42 2.38 2.38 0 00-2.48 2.44 2.42 2.42 0 002.46 2.51 2.25 2.25 0 002.25-1.41l2 .49a4.16 4.16 0 01-4.17 2.83 4.38 4.38 0 01-4.66-4.37zM96.91 237.05a4.37 4.37 0 014.57-4.36 4.19 4.19 0 014.28 2.81l-2 .48a2.28 2.28 0 00-2.24-1.42A2.39 2.39 0 0099 237a2.43 2.43 0 002.47 2.51 2.25 2.25 0 002.24-1.41l2 .49a4.15 4.15 0 01-4.24 2.79 4.39 4.39 0 01-4.56-4.33zM108.84 234.65v1.47h3.91v1.73h-3.91v1.6h4.54v1.8h-6.56v-8.4h6.57v1.8zM114 238.87l2-.58a2.35 2.35 0 002.26 1.39c.83 0 1.36-.37 1.36-.79s-.28-.6-.94-.81l-2.24-.67a2.42 2.42 0 01-2-2.22c0-1.38 1.35-2.5 3.23-2.5a4 4 0 013.85 2.2l-1.9.54a2.23 2.23 0 00-1.92-1c-.72 0-1.16.32-1.16.7s.21.49.58.6l2.2.67c1.3.4 2.39 1 2.39 2.36s-1.42 2.67-3.58 2.67a4.21 4.21 0 01-4.13-2.56zM122.19 238.87l2-.58a2.35 2.35 0 002.26 1.39c.83 0 1.35-.37 1.35-.79s-.27-.6-.93-.81l-2.24-.67a2.42 2.42 0 01-2-2.22c0-1.38 1.35-2.5 3.23-2.5a4 4 0 013.85 2.2l-1.91.54a2.2 2.2 0 00-1.92-1c-.71 0-1.15.32-1.15.7s.21.49.58.6l2.2.67c1.3.4 2.39 1 2.39 2.36s-1.42 2.67-3.58 2.67a4.2 4.2 0 01-4.13-2.56z" />
              <rect
                className={s.iconBg}
                x="147.53"
                y="219.88"
                width="55"
                height="55"
                rx="3"
              />
              <path
                className={s.vaultIcon}
                d="M162.45 234.8L175 260l12.63-25.16zm14 5h1.46v1.45h-1.46zm-2.9 5.83h-1.46v-1.46h1.46zm0-2.19h-1.46V242h1.46zm0-2.19h-1.46v-1.45h1.46zm2.19 6.57h-1.44v-1.46h1.46zm0-2.19h-1.44v-1.46h1.46zm0-2.19h-1.44V242h1.46zm0-2.19h-1.44v-1.45h1.46zm.71.73h1.46v1.46h-1.46zm0 3.65v-1.46H178v1.46z"
              />
              <image
                className={s.dropShadow}
                width="75"
                height="75"
                transform="translate(249.32 101.91)"
                xlinkHref="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEsAAABLCAYAAAA4TnrqAAAACXBIWXMAAAsSAAALEgHS3X78AAAErklEQVR4Xu2c63LbNhCFPymy5PiSNI2nfQQ/nJ/HD+d3aJvGSazoYrE/gEMsIVDiTv6QNc7MDkhdaOHzWYDyeHfWNA1Vw7Q494I+ze4fZudeM2Y1T49ul8yGOCsD03c8JdlJt8fnAJ6EFSHZoHA+VTUmAA56vA9aEZZx0pwAZV4IC29KsnCaOOZRBHYEK3PTOxOLGDoXsCmkZZ52gvQK7E28xjgAhxxY3wIvUAtgaWIFXMSwwOz7xqgclqDsgC2wieM2PrYHmtn9Q2cd68CKrpqTQK2AS+Aqxvt4viK5LAc2Vtn02xOgbIA18BJjbl4r95Vh0U2/JQHMDfAhxi1wTYB2Ed8/hfWrMaNSb0MA9A14JswZUnoegMPs/mEmd7WwzFolZy0JbvoAfAI+A78BH+Pjl3RhjRWUJLe8EtJtTQD1L+EXDyk1d/F4Hkeg7Kw5aa0SrM/AH8AdAdwNAZbWrqnAUgpugR8EUMv4vNLyZxx3+QVKC7xgrQjpdktw1B3wJ/A7AeB7wg+akrME6yfwnTBHCPBe4mNLjjOmm4bmCaXhBcE914TU+0QAdUdKReusscvCWpNAbQiQrki7fTFb+tJQsOSuK9JC/zHGlJxld8IdaY3akDYsC6pz461FfqGT+ObcXQuSwy5J4DReMD1YMsiOMCfdQ9qbbjuX3jS0xxaYoC2z0cIau5SGEFJxQRdQ/q3kaE6lBd6+2H4XfJeNpe+JY5bclX/2wZlx7u9ZM0dMQXn25J//5DzmDFPpolMBlKvvs5+dWx+swbTfkoY6q4oKy6UKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6EKy6E+WKqgwoxvXh5n5QD/bxDPzu0crNIFpg6p9EsfNLdTRQO6SFuRbo4PHP+gsavJIp/D2XlYWCXaKrwuVair0hOm8b/ydj6lOGuCBUDz9NjEyjBL3Vaoq8rTVqoL9IFxFxhYE9j5bE3kRrCg2uM8Da2jVB6rCvU1oVT2mlQquycVPsE0YKlqVbGmW+orl7XuOiooN5Kr5CaVwz7TBbUlFDROoV2BNYFgfSXM6RthfmvCfOWwTpsCOF6zlIJy1Tpe6CuhGNOCEjjVE8M4gWnCMoFgPQN/A1/i8Q+Cw7YU3AXlNNRFbd8DVdpDqlxXqeyCcZfS2QVbzS/UpuAL8BcJ2AvJXSrkbNUHyzrLNojYES54Q38jjDHKmmBHqr5/JrQr+IcESwu+dsdWncY9pr2K+jqo+l7F5LfxOK9Utze3Y4Jm1xzBUrcQbVjqGPI9hhb7PXBonh5bYKUF3m6xmriq1mXfFQGmaovHmoJSvh7bhhfaEbUr5mtWq1MtoQRChePqcqRiclupbkGNCVp+v2Rvi7TU2FCHowMct4Q61WxMKSloi2zsu2UYKyyday2y0I7u5Ac1G2uf6DYdmxdizDtgn+zOeMhCj/na2LVPHjfHsHCmBkpqzJjHySaJv9pNsnQ+ZpXSMhwMaMU5CFafptirdAiUPv0SrLem/wD+zwF/YqGwSwAAAABJRU5ErkJggg=="
              />
            </g>
          </g>
        </g>
      </svg>
    </div>
  )
}
