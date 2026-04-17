import TxClient from "./TxClient";

export function generateStaticParams() {
  return [{ hash: "[hash]" }];
}

export default function TxDetail({ params }: { params: { hash: string } }) {
  return <TxClient hash={params.hash} />;
}
