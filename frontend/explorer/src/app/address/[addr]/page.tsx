import AddressClient from "./AddressClient";

export function generateStaticParams() {
  return [{ addr: "[addr]" }];
}

export default function AddressDetail({ params }: { params: { addr: string } }) {
  return <AddressClient addr={params.addr} />;
}
